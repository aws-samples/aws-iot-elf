## aws-iot-elf Windows Getting Started

To get this AWS IoT ELF example working with Python 2.7.11+ on Windows, you will want to:

1. install Python 2.7.11+ to run ELF,
2. install Git to interact with ELF's source code repository, and...
3. install `virtualenv` to keep this Python project running separate from other future projects.

### Installing `python`
Browse to the [latest python release](https://www.python.org/downloads/windows/) and click *"Latest Python 2 Release"* to get to the download page with the correct Windows installer for your machine.

Once the download is complete, launch the installation executable. Most likely you want to select *Install for All Users*. Then enter a directory: `C:\Users\<user_id>\dev\Python27\` (or equivalent).

**Note:** The rest of this guide's instructions assume you will install into a `dev` directory inside your `<user_id>` directory. Furthermore, the directory `C:\Users\<user_id>` will be referred to as `~` for the remainder of this and the main Getting Started documents.

Now, make sure the installer adds the Python executable to the Path. This dialog:

![Image](../master/docs/Python-install-add-to-path.PNG?raw=true)

..should look like this dialog.

![Image](../master/docs/Python-install-add-to-path-selected.PNG?raw=true)


Push `Next` until the Python installation is complete.

### Installing `git`
Just browse to [git-scm](https://git-scm.com/download/win) and the Windows installation will download automatically.

Once the download is complete, launch the installation executable. The rest of the AWS IoT ELF getting started guide assumes Git for Windows is installed using the defaults since they are usually fine for most people.

### Installing `virtualenv`
Now to keep the AWS IoT ELF python dependencies separate, you probably want to [install](https://virtualenv.pypa.io/en/stable/installation/) `virtualenv`. This can be done simply by using `pip` which was installed when you installed Python. Change to the `~\dev` directory and enter:

```
pip install virtualenv
```

You now have the necessary development commands installed on your Windows-based machine. Continue on and finish the rest of the non-specific [Getting Started](https://github.com/awslabs/aws-iot-elf).
