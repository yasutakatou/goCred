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

![2](https://user-images.githubusercontent.com/22161385/136405752-f4134a0b-5522-41b0-ac7e-4e872785d53a.png)
When *Expiration* expires, the server sends the update information to the Proxy and the client gets the update.

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
