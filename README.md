aws-iot-elf
===========

An Extremely Low Friction (ELF) AWS IoT python example client

Getting Started
---------------
To get this example working with Python 2.7+, you probably want to first [install](https://virtualenv.pypa.io/en/stable/) `virtualenv` and create a virtual environment (eq. `venv`).

Install boto3 1.3.1+ and paho-mqtt 1.1+ into the active virtual environment using: 
````
$ pip install -r requirements.txt
````
[Install](http://docs.aws.amazon.com/cli/latest/userguide/installing.html) and [configure](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) the AWS CLI.

When you configure the AWS CLI, the API Keys you install as the default profile or a [named profile](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles) should have at least the following privileges [[tbd delineation]]

For detailed help and configuration options, enter: ```python elf.py --help```

Related Resources
-----------------
* [AWS IoT Getting Started](http://docs.aws.amazon.com/kinesis/latest/dev/introduction.html)  
* [AWS SDK for Python](http://aws.amazon.com/sdkforpython)
* [Paho MQTT](http://eclipse.org/paho/)
* [Apache 2.0 License](http://aws.amazon.com/apache2.0)
