# aws-iot-elf

An AWS IoT python example client that strives to be Extremely Low Friction (ELF)

## Overview

The **AWS IoT ELF** python example client demonstrates how one can **Create** Things, **Send** messages to Things, and **Clean** up Things in the AWS IoT service using the AWS SDK for Python (aka. `boto3`). This example also demonstrates how to bring together `boto3` and the standard MQTT client `paho-mqtt` in a straightforward fashion.

#### Create Thing(s)
Once the AWS IoT ELF's *getting started* is complete, to create a single Thing in the AWS IoT service, simply type:
````
(venv)$ python elf.py create
````
To create a given number of Things (eg. `3`) in the AWS IoT service, type:
````
(venv)$ python elf.py create 3
````

#### Send Messages
To send messages using previously created Things, type:
````
(venv)$ python elf.py send
````

#### Clean Thing(s)
To clean up all previously created Things, type:
````
(venv)$ python elf.py clean
````

## Getting Started

To get this example working with Python 2.7+. First clone this repo to your local machine.
````
$ git clone https://github.com/awslabs/aws-iot-elf.git
````
Then to keep the AWS IoT ELF python dependencies separate, you probably want to [install](https://virtualenv.pypa.io/en/stable/) `virtualenv` and create a virtual environment (eg. `$ virtualenv venv`). 

Now install the AWS IoT ELF dependencies into your local environment using: 
````
$ pip install -r requirements.txt
````
Next, [install](http://docs.aws.amazon.com/cli/latest/userguide/installing.html) and [configure](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) the AWS CLI.

When you configure the AWS CLI, the API Keys you install as the default profile or a [named profile](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles) should have at least the following privileges in an associated policy:
````
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
````

Lastly, to [Authenticate with AWS IoT](http://docs.aws.amazon.com/iot/latest/developerguide/identity-in-iot.html) using Server Authentication you will need to download the [Verisign root CA](https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem) and save it as a file `aws-iot-rootCA.crt`, or simply execute this command in the same directory as `elf.py`.
````
curl -o aws-iot-rootCA.crt https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem
````

## Detailed Help
#### Defaults
The AWS IoT ELF uses the following defaults:
- region: `us-west-2`
- MQTT topic: `elf/<thing_#>`
- message: `IoT ELF Hello`
- send message duration: `10 seconds`

#### Create Thing(s)
Using the `clean` command will invoke the `create_things(cli)` function with the given command line arguments.

To create a given number of Things (eg. `3`) in the AWS IoT service in a specific region, type:
````
(venv)$ python elf.py --region <region_name> create 3
````
This command results in three numbered things: `thing_0`, `thing_1`, and `thing_2` being created in `<region_name>`.

To create a single Thing in the AWS IoT service using a different AWS CLI profile, type:
````
(venv)$ python elf.py --profile <profile_name> create
````

To create a single Thing in the AWS IoT service in a specific region using a different AWS CLI profile, type:
````
(venv)$ python elf.py --region <region_name> --profile <profile_name> create
````

Calling the `create` command with a `--region` and/or `--profile` CLI option means that the Things will be created in that region and will use the corresponding AWS API Key and AWS Secret Key pair. Additional `send` and `clean` commands should use the same options. In this way the AWS IoT ELF will send messages to the same region and with the same profile used to `create` the Things in the first place. Once `clean` is called successfully, different `--region` and/or `--profile` option values can be used to orient the AWS IoT ELF differently.

When looking through the `create_thing(cli)` function, the core of the `create` command is shown in these lines of code:
````
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
````
Everything else around this code is to prepare for or record the results of the invocation of these functions.

#### Send Messages
Using the `send` command will invoke the `send_messages(cli)` function with the given command line arguments.

To send a specific message on a specific topic for a specified duration in another region, type:
````
(venv)$ python elf.py --region <region_name> send --topic 'elf/example' --duration <num_seconds> 'Example ELF message'
````

#### Clean Thing(s)
Using the `clean` command will invoke the `clean_up(cli)` function with the given command line arguments.

To force a clean up of only the local stored files, type:
````
(venv)$ python elf.py clean --only-local
````

When looking through the `clean_up(cli)` function, the core of the `clean` command is shown in these lines of code:
````
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
````
All steps prior to `delete_thing` are required, in order to detach and clean up a fully functional and authorized Thing.

#### Help
For additional detailed help and configuration options, enter: 
````
(venv)$ python elf.py --help
..or..
(venv)$ python elf.py create --help
(venv)$ python elf.py send --help
(venv)$ python elf.py clean --help
````

## Troubleshooting
**Q:** When I try to send messages, I see a `ResourceAlreadyExistsException` exception similar to the following. What might be wrong?
````
...example...
botocore.exceptions.ClientError: An error occurred (ResourceAlreadyExistsException) when calling the 
CreatePolicy operation: Policy cannot be created - name already exists (name=policy-thing_0)
````
**A:** In this example exception, for some reason the policy name `policy-thing_0` already exists and is colliding with the new policy to be created and applied to the Thing. The old existing policy needs to be [Detached](http://docs.aws.amazon.com/cli/latest/reference/iot/detach-principal-policy.html) and [Deleted](http://docs.aws.amazon.com/cli/latest/reference/iot/delete-policy.html) manually using the AWS CLI or AWS IoT Console. 

**Q:** When I try to `create`, `send`, or `clean`, I see an `AccessDeniedException` exception similar to the following. What might be wrong?
````
...example...
botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the 
CreateKeysAndCertificate operation: User: arn:aws:iam::XXXXXXYYYYYY:user/elf is not 
authorized to perform: iot:CreateKeysAndCertificate
````
**A:** In this example exception, the user `elf` does not have enough privilege to perform the `iot:CreateKeysAndCertificate` action on the AWS IoT service. Make sure the privileges as described in the *Getting Started* section are associated with the user or `--profile` (and specifically the API keys) experiencing the exception. 

**Q:** When I try to `send` messages using my recently created Things, I see a `ResourceNotFoundException` similar to the following. What might be wrong?
````
...example...
botocore.exceptions.ClientError: An error occurred (ResourceNotFoundException) when calling the 
AttachPrincipalPolicy operation: The certificate given in the principal does not exist.
````
**A:** In this example exception, the certificate recorded into the AWS IoT ELF config file does not exist in the region. Most likely the `create` command was called with a `--region` option that is not the same as the `--region` used when calling the `send` command.

Related Resources
-----------------
* [AWS IoT Getting Started](http://docs.aws.amazon.com/kinesis/latest/dev/introduction.html)  
* [AWS SDK for Python](http://aws.amazon.com/sdkforpython)
* [Paho MQTT](http://eclipse.org/paho/)
* [Apache 2.0 License](http://aws.amazon.com/apache2.0)
