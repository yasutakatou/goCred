# goCred (document writing..)
**Aws credential solution by Golang**

# Solution
Is your team managing AWS credentials properly?
Are you paying out credentials with strong permissions in perpetuity for reasons such as the hassle of renewal?
Also, you have no control over how long and with what privileges the credential will be used.
Are you treating credentials the same way you treat old password operations?
This tool will provide strong privileges to development users without the need to create credentials

# Feature
This is a solution that automatically renews the strong permissions of aws cloudshell at each deadline through a relay server.

# Architecture

1. AWS Cloudshell

```
curl -H"Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN" $AWS_CONTAINER_CREDENTIALS_FULL_URI
```

2. Server mode

3. Proxy mode

4. Client mode

```
SSL & AES encrypted Credential by Token
_____________         __________         ___________
|Server mode | ----> |Proxy mode| <---- |Client mode|
-------------         ----------         -----------
|Cloudshell  |       Tokenized Data     SSL & Dencrypt by Token
-------------
```

# installation

# options

# license
3-clause BSD License
