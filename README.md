# aws-iot-elf

An AWS IoT python example client that strives to be Extremely Low Friction (ELF)

## Overview

The **AWS IoT ELF** python example client demonstrates how one can **Create** Things, **Send** messages to Things, and **Clean** up Things in the AWS IoT service using the AWS SDK for Python (aka. `boto3`). This example also demonstrates how to bring together `boto3` and the standard MQTT client `paho-mqtt` in a straightforward fashion.

#### Create Thing(s)
Once the AWS IoT ELF's *getting started* is complete, to create a single Thing in the AWS IoT service, simply type:
```
(venv)$ python elf.py create
```
To create a given number of Things (eg. `3`) in the AWS IoT service, type:
```
(venv)$ python elf.py create 3
```

#### Send Messages
To send messages using previously created Things, type:
```
(venv)$ python elf.py send
```

#### Clean Thing(s)
To clean up all previously created Things, type:
```
(venv)$ python elf.py clean
```

## Getting Started

To get this example working with Python 2.7+. First clone this repo to your local machine.
```
$ cd ~
$ mkdir dev
$ cd ~/dev
$ git clone https://github.com/awslabs/aws-iot-elf.git
```
This will create a local folder `~/dev/aws-iot-elf`.

To keep the AWS IoT ELF python dependencies separate, you probably want to [install](https://virtualenv.pypa.io/en/stable/) `virtualenv`. If you choose to install `virtualenv` then create a virtual environment:
```
$ cd ~/dev/aws-iot-elf
$ virtualenv venv
```
...and then activate that virtual environment
```
$ source ~/dev/aws-iot-elf/venv/bin/activate
```

Now install the AWS IoT ELF dependencies into your local environment using these commands: 
```
(venv)$ cd ~/dev/aws-iot-elf
(venv)$ pip install -r requirements.txt
```
Next, [install](http://docs.aws.amazon.com/cli/latest/userguide/installing.html) and [configure](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) the AWS CLI.

When you configure the AWS CLI, the API Keys you install as the default profile or a [named profile](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles) should have at least the following privileges in an associated policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ELFStmt20160531",
            "Effect": "Allow",
            "Action": [
                "iot:AttachPrincipalPolicy",
                "iot:AttachThingPrincipal",
                "iot:CreateKeysAndCertificate",
                "iot:CreatePolicy",
                "iot:CreateThing",
                "iot:CreateTopicRule",
                "iot:DeleteCertificate",
                "iot:DeletePolicy",
                "iot:DeleteThing",
                "iot:DeleteTopicRule",
                "iot:DescribeEndpoint",
                "iot:DetachPrincipalPolicy",
                "iot:DetachThingPrincipal",
                "iot:ReplaceTopicRule",
                "iot:UpdateCertificate",
                "iot:UpdateThing"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

Now to [Authenticate with AWS IoT](http://docs.aws.amazon.com/iot/latest/developerguide/identity-in-iot.html) using Server Authentication you will need to download the [Verisign root CA](https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem) and save it as a file `aws-iot-rootCA.crt`, or simply execute this command in the same directory as `elf.py`.
```
(venv)$ curl -o aws-iot-rootCA.crt https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem
```

Lastly, you will probably want to read through the Troubleshooting section at the bottom of these instructions, just in case you experience a bump. 

## Detailed Help
#### Defaults
The AWS IoT ELF uses the following defaults:
- region: `us-west-2`
- MQTT topic: `elf/<thing_#>`
- message: `IoT ELF Hello`
- send message duration: `10 seconds`

#### Create Thing(s)
Using the `clean` command will invoke the [`create_things(cli)`](https://github.com/awslabs/aws-iot-elf/blob/master/elf.py#L286) function with the given command line arguments.

To create a given number of Things (eg. `3`) in the AWS IoT service in a specific region, type:
```
(venv)$ python elf.py --region <region_name> create 3
```
This command results in three numbered things: `thing_0`, `thing_1`, and `thing_2` being created in `<region_name>`.

To create a single Thing in the AWS IoT service using a different AWS CLI profile, type:
```
(venv)$ python elf.py --profile <profile_name> create
```

To create a single Thing in the AWS IoT service in a specific region using a different AWS CLI profile, type:
```
(venv)$ python elf.py --region <region_name> --profile <profile_name> create
```

Calling the `create` command with a `--region` and/or `--profile` CLI option means that the Things will be created in that region and will use the corresponding AWS CLI [named profile](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles) API Key and Secret Key pair. Additional `send` and `clean` commands should use the same options. In this way the AWS IoT ELF will send messages to the same region and with the same profile used to `create` the Things in the first place. Once `clean` is called successfully, different `--region` and/or `--profile` option values can be used to orient the AWS IoT ELF differently.

When looking through the `create_thing(cli)` function, the core of the `create` command is shown in these lines of code:
```python
...
    # generate a numbered thing name
    t_name = thing_name_template.format(i)
    # Create a Key and Certificate in the AWS IoT Service per Thing
    keys_cert = iot.create_keys_and_certificate(setAsActive=True)
    # Create a named Thing in the AWS IoT Service
    iot.create_thing(thingName=t_name)
    # Attach the previously created Certificate to the created Thing
    iot.attach_thing_principal(
        thingName=t_name, principal=keys_cert['certificateArn'])
...
```
Everything else around this code is to prepare for or record the results of the invocation of these functions.

Lastly, when you run the `create` commad you can see in the exmaple output below that a thing named `thing_0` was created and associated with a certificate in region `us-west-2`.
```
$ python elf.py create
..iot-elf:INFO - Read ELF ID from config: 95bb3ad5-95d1-4c9a-b818-b23f92fcde30
..iot-elf:INFO - [create_things] ELF creating 1 thing
..iot-elf:INFO - Thing:'thing_0' associated with cert:'arn:aws:iot:us-west-2:EXAMPLE1261:cert/EXAMPLEEXAMPLEEXAMPLEb326b72e76c2f67ccd6f8ec15515a9bd28168b2cc42'
..iot-elf:INFO - Thing Name: thing_0 and PEM file: ~/dev/aws-iot-elf/misc/thing_0.pem
..iot-elf:INFO - Thing Name: thing_0 Public Key File: ~/dev/aws-iot-elf/misc/thing_0.pub
..iot-elf:INFO - Thing Name: thing_0 Private Key File: ~/dev/aws-iot-elf/misc/thing_0.prv
..iot-elf:INFO - Wrote 1 things to config file: ~/dev/aws-iot-elf/misc/things.json
..iot-elf:INFO - [create_things] ELF created 1 things in region:'us-west-2'.
```

#### Send Messages
Using the `send` command will invoke the [`send_messages(cli)`](https://github.com/awslabs/aws-iot-elf/blob/master/elf.py#L360) function with the given command line arguments.

To send a specific message on a specific topic for a specified duration in another region, type:
```
(venv)$ python elf.py --region <region_name> send --topic 'elf/example' --duration <num_seconds> 'Example ELF message'
```

#### Clean Thing(s)
Using the `clean` command will invoke the [`clean_up(cli)`](https://github.com/awslabs/aws-iot-elf/blob/master/elf.py#L405) function with the given command line arguments. This will remove all resources that were created by ELF in the AWS IoT service and on the local file system. 

If you want to force only a clean up of the locally stored files, type:
```
(venv)$ python elf.py clean --only-local
```

When looking through the `clean_up(cli)` function, the core of the `clean` command is shown in these lines of code:
```python
..snip..
    iot.detach_principal_policy(
        policyName=thing[policy_name_key],
        principal=thing['certificateArn']
    )
..snip..
    iot.delete_policy(
        policyName=thing[policy_name_key]
    )
..snip..
    iot.update_certificate(
        certificateId=thing['certificateId'],
        newStatus='INACTIVE'
    )
..snip..
    iot.detach_thing_principal(
        thingName=thing_name,
        principal=thing['certificateArn']
    )
..snip..
    iot.delete_certificate(certificateId=thing['certificateId'])
..snip..
    iot.delete_thing(thingName=thing_name)
```
All steps prior to `delete_thing` are required, in order to detach and clean up a fully functional and authorized Thing.

#### Help
For additional detailed help and configuration options, enter: 
```
(venv)$ python elf.py --help
..or..
(venv)$ python elf.py create --help
(venv)$ python elf.py send --help
(venv)$ python elf.py clean --help
```

## Troubleshooting
**Q:** When I type in my command line I get a parameter parsing error. For example this command line gives an error:
```
$ python elf.py clean --region us-east-1
usage: elf.py [-h] [--region REGION] [--profile PROFILE_NAME]
              {create,send,clean} ...
elf.py: error: unrecognized arguments: --region us-east-1
```

**A:** This example error is caused when using the ELF Command Line because the order of the commands and options matters. The general structure of all ELF commands are: `python elf.py [global-elf-options] <command> [command-specific-options]`.  The `[global-elf-options]` should be the same across commands. The `[command-specific-options]` are specific to any given command. You can learn more about the various options by getting detailed help on the command line.

**Q:** I seem to need to upgrade my `openssl` and `python` installations. Why?

**A:** A version of [Python 2.7 ssl](https://docs.python.org/2/library/ssl.html) with support for Open SSL 1.0.1 is necessary to support the security posture (and specifically [TLSv1_2](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_1.2)) required by the AWS IoT service. 

**Q:** When I try to send messages, I see a `ResourceAlreadyExistsException` similar to the following. What might be wrong?
```
...example...
botocore.exceptions.ClientError: An error occurred (ResourceAlreadyExistsException) when calling the 
CreatePolicy operation: Policy cannot be created - name already exists (name=policy-thing_0)
```
**A:** In this example exception, for some reason the policy name `policy-thing_0` already exists and is colliding with the new policy to be created and applied to the Thing. The old existing policy needs to be [Detached](http://docs.aws.amazon.com/cli/latest/reference/iot/detach-principal-policy.html) and [Deleted](http://docs.aws.amazon.com/cli/latest/reference/iot/delete-policy.html) manually using the AWS CLI or AWS IoT Console. 

**Q:** When I try to `create`, `send`, or `clean`, I see an `AccessDeniedException` similar to the following. What might be wrong?
```
...example...
botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the 
CreateKeysAndCertificate operation: User: arn:aws:iam::XXXXXXYYYYYY:user/elf is not 
authorized to perform: iot:CreateKeysAndCertificate
```
**A:** In this example exception, the user `elf` does not have enough privilege to perform the `iot:CreateKeysAndCertificate` action on the AWS IoT service. Make sure the privileges as described in the *Getting Started* section are associated with the user or `--profile` (and specifically the API keys) experiencing the exception. 

**Q:** When I try to `send` messages using my recently created Things, I see a `ResourceNotFoundException` similar to the following. What might be wrong?
```
...example...
botocore.exceptions.ClientError: An error occurred (ResourceNotFoundException) when calling the 
AttachPrincipalPolicy operation: The certificate given in the principal does not exist.
```
**A:** In this example exception, the certificate recorded into the AWS IoT ELF config file does not exist in the region. Most likely the `create` command was called with a `--region` option that is not the same as the `--region` used when calling the `send` command.

Related Resources
-----------------
* [AWS IoT Getting Started](http://docs.aws.amazon.com/kinesis/latest/dev/introduction.html)  
* [AWS SDK for Python](http://aws.amazon.com/sdkforpython)
* [Paho MQTT](http://eclipse.org/paho/)
* [Apache 2.0 License](http://aws.amazon.com/apache2.0)
