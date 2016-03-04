package profilecreds

import (
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/bgentry/speakeasy"

	"github.com/go-ini/ini"
	"github.com/mitchellh/go-homedir"
)

// ProviderName provides a name for AssumeRoleMFA provider
const ProviderName = "AssumeRoleProfileProvider"

// DefaultDuration is the default amount of time in minutes that the credentials
// will be valid for.
var DefaultDuration = time.Duration(15) * time.Minute

// AssumeRoleProfileProvider retrieves temporary credentials from the STS service, using the configuration in
// the AWS CLI config file (usually $HOME/.aws/config). MFA is supported
// This provider must be used explicitly, as it is not included in the credentials chain.
type AssumeRoleProfileProvider struct {
	credentials.Expiry

	// Expiry duration of the STS credentials. Defaults to 15 minutes if not set.
	Duration time.Duration

	// The profile to read from the AWS CLI config file (usually $HOME/.aws/config).
	ProfileName string

	// Optional cache to use for persisting credentials. This is particularly useful
	// when using MFA in a CLI application, so as to not enter the token for each run.
	Cache Cache

	// Optional source for the MFA token. The default is to prompt the user to enter
	// the token on stdin.
	GetToken TokenSource

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	//
	// If using MFA, this will fail unless a new token can be provided
	ExpiryWindow time.Duration
}

type profile struct {
	// Profile name
	Name string

	// Role to be assumed.
	RoleARN string

	// Name of the source profile which has the credentials to assume the role.
	SourceProfileName string

	// Optional session name, if you wish to reuse the credentials elsewhere.
	RoleSessionName *string

	// Optional serial number (hardware) or ARN (software) of the MFA device.
	MFASerial *string

	// Optional ExternalID to pass along, defaults to nil if not set.
	ExternalID *string
}

// NewCredentials returns a pointer to a new Credentials object retrieved
// by assuming the specified profile
func NewCredentials(profileName string, options ...func(*AssumeRoleProfileProvider)) *credentials.Credentials {
	p := &AssumeRoleProfileProvider{
		ProfileName: profileName,
		Duration:    DefaultDuration,
	}

	for _, option := range options {
		option(p)
	}

	return credentials.NewCredentials(p)
}

// Retrieve generates a new set of temporary credentials using STS.
func (p *AssumeRoleProfileProvider) Retrieve() (credentials.Value, error) {
	prof, err := p.loadProfile()
	if err != nil {
		return credentials.Value{ProviderName: ProviderName}, err
	}

	cachedCreds := p.loadCachedCreds()
	if cachedCreds.Match(prof) && !cachedCreds.IsExpired() {
		return cachedCreds.Credentials, nil
	}
	if p.GetToken == nil {
		p.GetToken = PromptTokenSource
	}
	credentials, expiration, err := p.retrieve(*prof)

	cachedCreds = &creds{
		Profile:     *prof,
		Credentials: credentials,
		Expiration:  expiration,
	}

	if cachedJSON, err := json.Marshal(cachedCreds); err == nil {
		p.Cache.Set("credentials", string(cachedJSON))
	}

	return cachedCreds.Credentials, nil
}

func (p *AssumeRoleProfileProvider) loadProfile() (*profile, error) {
	home, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	config, err := ini.Load(home + "/.aws/config")
	if err != nil {
		return nil, err
	}

	section, err := config.GetSection("profile " + p.ProfileName)
	if err != nil {
		return nil, err
	}

	prof := &profile{
		Name: p.ProfileName,
	}

	if k, err := section.GetKey("role_arn"); err == nil {
		prof.RoleARN = k.String()
	} else {
		return nil, err
	}

	if k, err := section.GetKey("source_profile"); err == nil {
		prof.SourceProfileName = k.String()
	} else {
		return nil, err
	}

	if k, err := section.GetKey("mfa_serial"); err == nil {
		prof.MFASerial = aws.String(k.String())
	}

	if k, err := section.GetKey("external_id"); err == nil {
		prof.ExternalID = aws.String(k.String())
	}

	if k, err := section.GetKey("role_session_name"); err == nil {
		prof.RoleSessionName = aws.String(k.String())
	}

	return prof, nil
}

func (p *AssumeRoleProfileProvider) loadCachedCreds() *creds {
	var cached creds

	if cachedJSON, ok := p.Cache.Get("credentials"); ok {
		json.Unmarshal([]byte(cachedJSON), &cached)
	}

	return &cached
}

func (p *AssumeRoleProfileProvider) retrieve(prof profile) (credentials.Value, time.Time, error) {
	sourceCreds := credentials.NewSharedCredentials("", prof.SourceProfileName)

	// Apply defaults where parameters are not set.
	if prof.RoleSessionName == nil {
		// Try to work out a role name that will hopefully end up unique.
		prof.RoleSessionName = aws.String(fmt.Sprintf("%d", time.Now().UTC().UnixNano()))
	}
	if p.Duration == 0 {
		// Expire as often as AWS permits.
		p.Duration = DefaultDuration
	}

	sess := session.New()
	client := sts.New(sess, sess.Config.WithCredentials(sourceCreds))

	params := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(p.Duration / time.Second)),
		RoleArn:         aws.String(prof.RoleARN),
		RoleSessionName: prof.RoleSessionName,
		ExternalId:      prof.ExternalID,
	}
	if prof.MFASerial != nil {
		params.SerialNumber = prof.MFASerial

		token, err := p.GetToken()
		if err != nil {
			return credentials.Value{ProviderName: ProviderName}, time.Now(), err
		}
		params.TokenCode = &token
	}

	roleOutput, err := client.AssumeRole(params)
	if err != nil {
		return credentials.Value{ProviderName: ProviderName}, time.Now(), err
	}

	return credentials.Value{
		AccessKeyID:     *roleOutput.Credentials.AccessKeyId,
		SecretAccessKey: *roleOutput.Credentials.SecretAccessKey,
		SessionToken:    *roleOutput.Credentials.SessionToken,
		ProviderName:    ProviderName,
	}, (*roleOutput.Credentials.Expiration).UTC(), nil
}

type creds struct {
	Credentials credentials.Value

	Expiration time.Time

	Profile profile
}

func (c *creds) Match(p *profile) bool {
	return reflect.DeepEqual(c.Profile, *p)
}

func (c *creds) IsExpired() bool {
	return c.Expiration.UTC().Before(time.Now().UTC())
}

// TokenSource provides an MFA token
type TokenSource func() (string, error)

// PromptTokenSource is the default MFA token source. It prompts the user for a token on stdin.
var PromptTokenSource = func() (string, error) {
	return speakeasy.Ask("MFA Token: ")
}
