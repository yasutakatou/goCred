# goCred (document writing..)
**Aws credential solution by Golang (Works on Linux, Arm, and Windows)**

# Solution
Is your team managing AWS credentials properly?
Are you paying out credentials with strong permissions in perpetuity for reasons such as the hassle of renewal?
Also, you have no control over how long and with what privileges the credential will be used.
Are you treating credentials the same way you treat old password operations?
This tool will provide strong privileges to development users without the need to create credentials

# Feature
This is a solution that automatically renews the strong permissions of aws cloudshell at each deadline through a relay server.
In cloudshell, credentials similar to account privileges can be obtained in the following way.

```
curl -H"Authorization: $AWS_CONTAINER_AUTHORIZATION_TOKEN" $AWS_CONTAINER_CREDENTIALS_FULL_URI
```

This tool prepares a proxy and delivers the same credentials to the client.
The benefits of this are as follows
- No need to create authoritative credentials.
- No more accidents due to failure to update credentials that have been created.

# Architecture

```
SSL & AES encrypted Credential by Token
_____________         __________         ___________
|Server mode | ----> |Proxy mode| <---- |Client mode|
-------------         ----------         -----------
|Cloudshell  |       Tokenized Data     SSL & Dencrypt by Token
-------------
```

1. Server mode

Get the credentials from AWS cloudshell, encrypt them with a token, and then forward them to the Proxy server.

2. Proxy mode

Save the credentials for each token.

note) Since the proxy server needs to be accessed by both the server and the client, the credentials are stored in encrypted form.
The estimate is that if a string is leaked, it will take an update of the credential before it can be compounded.

3. Client mode

Get the encrypted credentials that came to access with the token as a password, and compound them with the token.

![2](https://user-images.githubusercontent.com/22161385/136405752-f4134a0b-5522-41b0-ac7e-4e872785d53a.png)
When *Expiration* expires, the server sends the update information to the server and the client gets the update.

# installation

If you want to put it under the path, you can use the following.

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

# Usage

**note) prepare cert file beforehand. (use mkcert and such more)**

- Access AWS Management Console and Cloudshell
- Put binary on Cloudshell
![1](https://user-images.githubusercontent.com/22161385/136404976-559421c4-2405-4ef7-aa44-8ffe977e8c45.png)
or
```
curl -OL https://github.com/yasutakatou/goCred/releases/download/XXX/goCred_linux_amd64.zip
unzip goCred_linux_amd64.zip
chmod 755 goCred
```
note) The XXX part should be the latest version.

- Run Proxy
![3](https://user-images.githubusercontent.com/22161385/136408942-9a564658-fcb2-44e3-90d0-cd40955c31b8.png)


- Run Server on Cloudshell
[5](https://user-images.githubusercontent.com/22161385/136409115-11bb71f5-c60c-4765-bd8b-5397180667ff.png)

- Run Client
![6](https://user-images.githubusercontent.com/22161385/136409249-aa1379d1-5488-4778-8c8d-4c2ce0fc48ba.png)

- every credential limit
![7](https://user-images.githubusercontent.com/22161385/136409462-2d69c8c3-65f5-46d1-b3f7-a78d4e85ce58.png)


# options
```
Usage of goCred.exe:
  -cert string
        [-cert=ssl_certificate file path] (default "localhost.pem")
  -client
        [-client=Client mode (true is enable)]
  -cloudshell string
        [-cloudshell=AWS Cloudshell window titile] (default "CloudShell")
  -count int
        [-count=operating interval ] (default 60)
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
  -rpa
        [-rpa=CloudShell timeout guard (true is enable)] (default true)
  -server
        [-server=Server mode (true is enable)]
  -token string
        [-token=authentication token (if this value is null, is set random)]
  -try int
        [-try=error and try counter] (default 100)
  -wait int
        [-wait=loop wait Millisecond] (default 250)
```

## -cert string

ssl_certificate file path (if you don't use https, haven't to use this option)

## -client

This is the client mode to get the token from the proxy.
You need to specify the address of the proxy server where you want to get the token.

## -cloudshell string

This is the title of the CloudShell window that will be operated periodically when rpa is enabled.

## -count int

It's like a regular checkup of the condition.

## -debug

debug mode (true is enable)

## -key string

ssl_certificate_key file path (if you don't use https, haven't to use this option)

## -log

Specify the log file name.

## -port string

port number

## -proxy

Start in proxy mode and wait for server mode and client mode to connect.

## -rpa

CloudShell is a use that times out if no operation continues. With this option, you can enter a mode to avoid timeouts by periodically typing ENTER into CloudShell

note) If you don't use this feature, the default timeout will be 20 minutes.
note) For now, only Windows OS is supported. I need support for people who have MacOS.
note) A window showing CloudShell in a browser is required.
![image](https://user-images.githubusercontent.com/22161385/136655431-19721e8c-a612-4308-8054-ff21bad88cc5.png)

## -server

This is the mode to transfer credential from CloudShell to Proxy server.

## -token string

authentication token (if this value is null, is set random)
  
## -try int

error and try counter
**In case of wait next screen a while, set value larger.**

## -wait int

loop wait Millisecond

# license
3-clause BSD License
