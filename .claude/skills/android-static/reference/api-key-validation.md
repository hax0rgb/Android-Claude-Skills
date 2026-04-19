# API Key Validation Reference

When hardcoded API keys are found during static analysis, verify if they're exploitable using these techniques.
Source: [KeyHacks](https://github.com/streaak/keyhacks) + unmerged PRs.

## Key Pattern Detection (Regex)

### High-Value Targets
```
# AWS Access Key
AKIA[0-9A-Z]{16}

# AWS Cognito Identity Pool
us-east-1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}

# Google API Key
AIza[0-9A-Za-z_-]{35}

# Google reCAPTCHA Secret
^6[0-9a-zA-Z_-]{39}$

# Firebase FCM Server Key
AAAA[a-zA-Z0-9_-]{140,}

# Stripe Live Secret Key
sk_live_[0-9a-zA-Z]{24}

# Stripe Publishable Key (NOT exploitable)
pk_live_[0-9a-zA-Z]{24}

# GitHub Personal Access Token
ghp_[a-zA-Z0-9]{36}

# GitHub OAuth
gho_[a-zA-Z0-9]{36}

# Slack Token
xoxp-[0-9]+-[0-9]+-[0-9]+-[a-z0-9]+
xoxb-[0-9]+-[a-zA-Z0-9]+

# OpenAI API Key
sk-[a-zA-Z0-9]{20,}

# Twilio Account SID
AC[a-z0-9]{32}

# SendGrid
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}

# Mapbox
(pk|sk|tk)\.[a-zA-Z0-9]{60,}

# Square
sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}
EAAA[a-zA-Z0-9]{60}

# Azure
[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}

# NPM Token
//registry.npmjs.org/:_authToken=[0-9a-f-]{36}

# Private Keys
-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----
```

### Generic Secret Patterns
```
(api[_-]?key|apikey|secret|password|token|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}
```

## Verification Commands

### Cloud Services

**AWS:**
```bash
# Set creds and verify
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
aws sts get-caller-identity
# If valid: enumerate permissions
aws s3 ls
aws iam list-users
aws lambda list-functions
```

**AWS Cognito Identity Pool:**
```bash
aws cognito-identity get-id --identity-pool-id "us-east-1:xxxx-xxxx" --region us-east-1
aws cognito-identity get-credentials-for-identity --identity-id "<id>" --region us-east-1
# Use temp creds with enumerate-iam.py
```

**Google Cloud Service Account:**
```bash
gcloud auth activate-service-account --key-file=service_account.json
gcloud auth print-access-token
gcloud projects list
```

**Azure:**
```bash
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=<CLIENT_ID>&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=<SECRET>&grant_type=client_credentials" \
  "https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/token"
```

### Firebase / Google

**Firebase Database:**
```bash
# Append .json to database URL
curl "https://<project>.firebaseio.com/.json"
```

**FCM Server Key:**
```bash
curl -s -X POST --header "Authorization: key=<FCM_KEY>" \
  --header "Content-Type:application/json" \
  "https://fcm.googleapis.com/fcm/send" \
  -d '{"registration_ids":["ABC"]}'
# If valid: can send push notifications to any device
```

**Google Maps API Key (12 endpoints):**
```bash
# Staticmap (billable)
curl "https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key=<KEY>"
# Directions
curl "https://maps.googleapis.com/maps/api/directions/json?origin=A&destination=B&key=<KEY>"
# Geocoding
curl "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key=<KEY>"
```

### Communication / Messaging

**Slack:**
```bash
curl -sX POST "https://slack.com/api/auth.test?token=xoxp-TOKEN&pretty=1"
# If valid: list channels, read messages, post messages
```

**Twilio:**
```bash
curl -X GET "https://api.twilio.com/2010-04-01/Accounts.json" -u "ACCOUNT_SID:AUTH_TOKEN"
# If valid: send SMS, make calls
```

**SendGrid:**
```bash
curl -X GET "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer <TOKEN>"
# If valid: send emails
```

**Telegram Bot:**
```bash
curl "https://api.telegram.org/bot<TOKEN>/getMe"
# If valid: send messages, manage bot
```

### Payment Services

**Stripe Live Key:**
```bash
curl https://api.stripe.com/v1/charges -u "sk_live_XXXX:"
# If valid: view charges, create charges. sk_test_ keys are NOT exploitable.
```

**Razorpay:**
```bash
curl -u "<KEY_ID>:<KEY_SECRET>" https://api.razorpay.com/v1/payments
```

**PayPal:**
```bash
curl -v "https://api.sandbox.paypal.com/v1/oauth2/token" \
  -u "client_id:secret" -d "grant_type=client_credentials"
```

### AI Services

**OpenAI:**
```bash
curl -H "Authorization: Bearer sk-XXXX" https://api.openai.com/v1/models
# Financial risk: API usage costs
```

**Google Gemini:**
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"contents":[{"parts":[{"text":"test"}]}]}' \
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=<KEY>"
```

### CI/CD

**GitHub PAT:**
```bash
curl -s -H "Authorization: token ghp_XXXX" "https://api.github.com/user"
# Check: repos, orgs, emails
```

**CircleCI:**
```bash
curl "https://circleci.com/api/v1.1/me?circle-token=<TOKEN>"
```

**Travis CI:**
```bash
curl -H "Travis-API-Version: 3" -H "Authorization: token <TOKEN>" https://api.travis-ci.org/repos
```

### Monitoring / Infrastructure

**Datadog:**
```bash
curl "https://api.datadoghq.com/api/v1/dashboard?api_key=<KEY>&application_key=<APP_KEY>"
```

**New Relic:**
```bash
curl -X POST https://api.newrelic.com/graphql \
  -H "Content-Type: application/json" -H "API-Key: <KEY>" \
  -d '{"query":"{ requestContext { userId apiKey } }"}'
```

**Grafana:**
```bash
curl -s -H "Authorization: Bearer <KEY>" "http://<grafana>/api/user"
```

**Shodan:**
```bash
curl "https://api.shodan.io/api-info?key=<KEY>"
```

**Cloudflare:**
```bash
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer <TOKEN>"
```

### Storage / Content

**Dropbox:**
```bash
curl -X POST https://api.dropboxapi.com/2/users/get_current_account \
  -H "Authorization: Bearer <TOKEN>"
```

**HubSpot:**
```bash
curl "https://api.hubapi.com/owners/v2/owners?hapikey=<KEY>"
```

**MailChimp:**
```bash
# Extract datacenter from key (e.g., us1)
curl --request GET --url "https://<dc>.api.mailchimp.com/3.0/" --user "any:<API_KEY>"
```

## Severity Assessment

| Key Type | Impact if Valid | Severity |
|---|---|---|
| AWS with admin/broad IAM | Full infrastructure access | Critical |
| Stripe sk_live_ | Financial transactions | Critical |
| Database/storage creds | Data theft | Critical |
| FCM server key | Push notification spam | High |
| Slack token | Workspace data access | High |
| OpenAI/AI keys | Financial (API costs) | High |
| Google Maps key | Billing abuse | Medium |
| Stripe pk_live_ / sk_test_ | Non-exploitable | Info |

## Android-Specific Notes

- Keys commonly found in: `strings.xml`, `BuildConfig.java`, `AndroidManifest.xml` meta-data, `.properties` files, hardcoded in Java/Kotlin source
- Firebase config: check `google-services.json` in decompiled APK
- AWS Cognito pool IDs: check for unauthenticated identity access
- Check `res/raw/` and `assets/` for config files containing keys
