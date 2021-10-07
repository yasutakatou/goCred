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

f you want to put it under the path, you can use the following.

```
go get github.com/yasutakatou/goCred
```

If you want to create a binary and copy it yourself, use the following.

```
git clone https://github.com/yasutakatou/goCred
cd goCred
go build .
```

[or download binary from release page](https://github.com/yasutakatou/goCred/releases). save binary file, copy to entryed execute path directory.

# options
```
Usage of ./goCred:
  -cert string
        [-cert=ssl_certificate file path] (default "localhost.pem")
  -client
        [-client=Client mode (true is enable)]
  -debug
        [-debug=debug mode (true is enable)]
  -key string
        [-key=ssl_certificate_key file path] (default "localhost-key.pem")
  -log
        [-log=logging mode (true is enable)]
  -port string
        [-prort=Port Number (Use Proxy mode)] (default "8080")
  -proxy
        [-proxy=Proxy mode (true is enable)]
  -server
        [-server=Server mode (true is enable)]
  -token string
        [-token=authentication token (if this value is null, is set random)]
```

## -cert string
## -client
## -debug
## -key string
## -log
## -port string
## -proxy
## -server
## -token string

# license
3-clause BSD License
