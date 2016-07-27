## aws-iot-elf Docker Getting Started

Instead of installing the required ELF components to your local system, you can build ELF as a Docker image and run from a system with Docker installed. Below is a sample dockerfile that can be used to build an ELF Docker image. Refer to the comments in the sample below and edit to match your environment:

```
FROM python:2.7.11
RUN apt-get update
RUN pip install awscli
RUN aws configure set aws_access_key_id YOUR_AWS_ACCESS_KEY_ID # provide aws access key id
RUN aws configure set aws_secret_access_key YOUR_AWS_SECRET_KEY # provide aws secret access key
RUN aws configure set default.region YOUR_AWS_REGION # provide aws default region
RUN git clone https://github.com/awslabs/aws-iot-elf /root/aws-iot-elf
RUN pip install -r /root/aws-iot-elf/requirements.txt
RUN curl -o /root/aws-iot-elf/aws-iot-rootCA.crt https://www.symantec.com/content/en/us/enterprise/verisign/roots/VeriSign-Class%203-Public-Primary-Certification-Authority-G5.pem
CMD /bin/bash
```

A few more notes to get started with your ELF Docker image:
- The access key credentials provided must be associated with an IAM policy that matches the permissions detailed in the  [Getting Started](https://github.com/awslabs/aws-iot-elf)
- ELF is a CLI tool, so the ELF container should be launched in interactive mode using the `-it` flags
- ELF stores information about the resources created locally (in the container's file system, in this case), so either make sure to clean up the resources you create before terminating the container, or stop the container instead of terminating it. Otherwise, you will need to manually clean up resources created by ELF.
- Once the container is launched, ELF is located in '/root/aws-iot-elf', and can be launched via
```python /root/aws-iot-elf/elf.py COMMAND```

You now have the necessary development commands configured in your ELF Docker image. Continue on and finish the rest of the non-specific [Getting Started](../master/README.md).


## Troubleshooting
**Q:** When running native Docker on Mac the signature time expired. The error message is similar to the following: 
``` 
raise ClientError(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (InvalidSignatureException) when calling the CreateKeysAndCertificate operation: Signature expired: 20160721T024247Z is now earlier than 20160721T184649Z (20160721T185149Z - 5 min.)
```

**A:** This issue is listed [here](http://stackoverflow.com/questions/22800624/will-docker-container-auto-sync-time-with-the-host-machine). To resolve this issue, restart the entire Docker daemon. Simply restarting the container will not resolve the issue.

