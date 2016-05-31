# aws-iot-elf

An Extremely Low Friction (ELF) AWS IoT python example client

## Overview

The **AWS IoT ELF** python example client provides an extremely low friction example of how one can **Create** Things, **Send** messages to Things, and **Clean** up Things in the AWS IoT service.

#### Create Thing(s)
Once the AWS Iot ELF is configured, to create a single Thing in the AWS IoT service, simply type:
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
            "Sid": "Stmt1464723918000",
            "Effect": "Allow",
            "Action": [
                "iot:AttachPrincipalPolicy",
                "iot:AttachThingPrincipal",
                "iot:Connect",
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
                "iot:Publish",
                "iot:Receive",
                "iot:ReplaceTopicRule",
                "iot:Subscribe",
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

## Details
#### Create Thing(s)
To create a given number of Things (eg. `3`) in the AWS IoT service in a specific region, type:
````
(venv)$ python elf.py --region <region_name> create 3
````

To create a single Thing in the AWS IoT service using a different AWS CLI profile, type:
````
(venv)$ python elf.py --profile elf create
````

#### Send Messages
To send a specific message on a specific topic for a specified duration in another region, type:
````
(venv)$ python elf.py --region <region_name> send --topic 'elf/example' --duration <num_seconds> 'Example ELF message'
````

#### Clean Thing(s)
To force a clean up of only the local stored files, type:
````
(venv)$ python elf.py clean --only-local
````

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
**Q:** When I try to send messages, I see a `ResourceAlreadyExistsException` exception similar to the following. What could be wrong?
````
...example...
  File "elf.py", line 182, in _create_and_attach_policy
    policyDocument=policy
  File "/Users/brettf/dev/iot/bites/aws-iot-elf/venv/lib/python2.7/site-packages/botocore/client.py", line 258, in _api_call
    return self._make_api_call(operation_name, kwargs)
  File "/Users/brettf/dev/iot/bites/aws-iot-elf/venv/lib/python2.7/site-packages/botocore/client.py", line 548, in _make_api_call
    raise ClientError(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (ResourceAlreadyExistsException) when calling the CreatePolicy operation: Policy cannot be created - name already exists (name=policy-elf-thing-0)
````
**A:** In this example exception, for some reason the policy name `policy-elf-thing-0` already exists and is colliding with the new policy being created and applied to the Thing. The old existing policy needs to be [Detached](http://docs.aws.amazon.com/cli/latest/reference/iot/detach-principal-policy.html) and [Deleted](http://docs.aws.amazon.com/cli/latest/reference/iot/delete-policy.html) manually using the AWS CLI or AWS IoT Console. 

**Q:** When I try to `create`, `send`, or `clean`, I see an `AccessDeniedException` exception similar to the following. What could be wrong?
````
...example...
File "elf.py", line 330, in create_things
    keys_cert = iot.create_keys_and_certificate(setAsActive=True)
  File "/Users/brettf/dev/iot/bites/aws-iot-elf/venv/lib/python2.7/site-packages/botocore/client.py", line 258, in _api_call
    return self._make_api_call(operation_name, kwargs)
  File "/Users/brettf/dev/iot/bites/aws-iot-elf/venv/lib/python2.7/site-packages/botocore/client.py", line 548, in _make_api_call
    raise ClientError(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the CreateKeysAndCertificate operation: User: arn:aws:iam::XXXXXXYYYYYY:user/elf is not authorized to perform: iot:CreateKeysAndCertificate
````
**A:** In this example exception, the user `elf` does not have enough privilege to perform the `iot:CreateKeysAndCertificate` action on the AWS IoT service. Make sure the privileges as described in the *Getting Started* section are associated with the user (and specifically API keys) experiencing the exception.

Related Resources
-----------------
* [AWS IoT Getting Started](http://docs.aws.amazon.com/kinesis/latest/dev/introduction.html)  
* [AWS SDK for Python](http://aws.amazon.com/sdkforpython)
* [Paho MQTT](http://eclipse.org/paho/)
* [Apache 2.0 License](http://aws.amazon.com/apache2.0)
