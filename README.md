## aws-iot-elf

An Extremely Low Friction (ELF) AWS IoT python example client

The **AWS IoT ELF** python example client provides an extremely low friction example of how one can **create** Things, **send** messages to Things, and **clean** up Things in the AWS IoT service.

#### Create Thing(s)
To create a single Thing in the AWS IoT service, simply type:
````
(venv)$ python elf.py create
````
To create a given number of Things (eg. `3`) in the AWS IoT service, simply type:
````
(venv)$ python elf.py create 3
````

#### Send Messages
To send messages using previously created Things, simply type:
````
(venv)$ python elf.py send
````

#### Clean Thing(s)
To clean up all previously created Things, simply type:
````
(venv)$ python elf.py clean
````

### Getting Started

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

When you configure the AWS CLI, the API Keys you install as the default profile or a [named profile](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles) should have at least the following privileges [[tbd delineation]].

Lastly, to [Authenticate with AWS IoT](http://docs.aws.amazon.com/iot/latest/developerguide/identity-in-iot.html) using Server Authentication you will need to download the [Verisign root CA](https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem) and save it as a file `aws-iot-rootCA.crt`, or simply execute this command in the same directory as `elf.py`.
````
curl -o aws-iot-rootCA.crt https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem
````

For detailed help and configuration options, enter: ```python elf.py --help```

Related Resources
-----------------
* [AWS IoT Getting Started](http://docs.aws.amazon.com/kinesis/latest/dev/introduction.html)  
* [AWS SDK for Python](http://aws.amazon.com/sdkforpython)
* [Paho MQTT](http://eclipse.org/paho/)
* [Apache 2.0 License](http://aws.amazon.com/apache2.0)
