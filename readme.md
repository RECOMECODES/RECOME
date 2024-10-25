# RECOME-Public

## Overview

The project consists four components(packages): `metrics_filter`(Metrics Filter, Section 3.2.1), `hash_filter`(Line Hash Filter, Section 3.2.2),
`patch_filter`(Addition and Deletion Lines Check, Section 3.3.1), `patch_compare`(Metrics Distance Check, Section 3.3.2).

Besides, we provide utils classes in `Dataset` package to load dataset, including the `Old-New-Funcs` dataset and a class to load the target system (`Dataset/target_project.py`).

During the detection, `cache`, `log`, `processed`, `result` four directories are used.

We provide dockerfile and a flask server(`server.py`), so you can build the project to docker and use HTTP Request to detect vulnerability.

## Installation

### Install Python Requirements

#### conda

```shell
conda env new -f environment.yml
```

#### pip
```shell
pip install -r requirements.txt
```

#### requirement list

- Flask==3.0.3
- loguru==0.7.2
- mmh3==4.1.0
- multiset==3.0.1
- numpy==1.26.4
- pandas==2.2.2
- PyYAML==6.0.1
- tqdm==4.66.2
- tree_sitter==0.20.4

#### About Ctags

Since Ctags is a lightweight open-source software, we put its binary version in `Database/universal-ctags` with COPYING.
So you don't need to install it.  

```bash
./dependency/ctags --version
```
```
Universal Ctags 6.0.0(293f11e), Copyright (C) 2015-2022 Universal Ctags Team
Universal Ctags is derived from Exuberant Ctags.
Exuberant Ctags 5.8, Copyright (C) 1996-2009 Darren Hiebert
  Compiled: Dec 20 2023, 10:38:07
  URL: https://ctags.io/
  Output version: 0.0
  Optional compiled features: +wildcards, +regex, +gnulib_regex, +iconv, +option-directory, +xpath, +json, +interactive, +yaml, +packcc, +optscript
```

#### About treesitter .so lib

We create a parser .so lib in our dependency folder according to the guide provided by tree-sitter official, which helps to parse c/cpp files.


## Datasets

We use Old-New-Funcs dataset to store all the vulnerabilities and patches pairs which is used in all the components of RECOME.

### Old-New-Funcs Dataset

We suggest to put the dataset to `resource/OldNewFuncs`.

Unfortunately we can not open source the dataset we used in this project, but you can build one using your own data following the structure below.

An Example of the Old-New-Funcs dataset folder structure:

```
|-- OldNewFuncs
|   |-- ffmpeg (software directory)
|   |   |-- CVE-2009-0385 (CVE directory)
|   |   |   |-- CVE-2009-0385_CWE-189_72e715fb798f2cb79fd24a6d2eaeafb7c6eeda17_4xm.c_1.1_fourxm_read_header_OLD.vul [Vulnerable Version]
|   |   |   |-- CVE-2009-0385_CWE-189_72e715fb798f2cb79fd24a6d2eaeafb7c6eeda17_4xm.c_1.1_fourxm_read_header_NEW.vul [Patch Version]
|   |   |   |-- ...Other Old-New-Funcs files (with the filename extension `.vul`)
|   |   |-- ...Other CVEs
|   |-- ...Other Software
```

We do not utilize the software and CVE directory name. However, we utilize the old-new-funcs file's filename 
in our project. Each Old-New-Funcs file should store a function.

The Old-New-Funcs filename structure:
```
[CVE-No.]_[CWE-No.]_[Commit]_[File Extracted From]_[Version]_[Function Name]_[OLD/NEW].vul
```
`OLD` tag refers to vulnerability version, while `NEW` tag refers to patch version. 

We utilized the `OLD/NEW` part of the filename in RECOME. So please set them properly.

## How To Run

### Run Locally

Make sure you have properly installed all the requirements and prepared the datasets before run.

You can execute `python3 main --help` to read the help message of this project.

We run RECOME on Linux (recommended), you can try if it can run on Windows or other operating systems.

#### Basic Usage
```bash
python3 main.py /path/to/target/system
```

#### Help Message
```bash
python3 main.py --help
```
```
usage: main.py [-h] [--rebuild [{old-new-funcs,target} ...]] project

Extract data from project dir

positional arguments:
  project               Path to the project dir

options:
  -h, --help            show this help message and exit
  --rebuild [{old-new-funcs,target} ...]
                        Rebuild any of the components/dataset cache
```

#### Rebuild Option

We provide rebuild option to rebuild the cache if there are any updates to the dataset. We suggest to apply all the rebuild options first time before running the project.

If you update Old-New-Funcs Dataset, please rebuild `old-new-funcs`.

If you do not specify any rebuild options, `target` option is set default to extract function of the target system each time before the vulnerbility detection.

Use space to separate the option if you want to apply multiple rebuild option.

#### Results

Detection results not only display in the console, but also in the `result` folder as well. You can find the detection result in `result/[target-system]`.

### Run Remote or In Docker

Run `server.py` if you want to run RECOME remote. If you use docker, `server.py` runs automatically.
This will open a flask server on port 8000 on the machine/docker. You can change the port in the `server.py`.

```bash
python3 server.py
```

You can publish a vulnerability detecting job using the following HTTP requests.

#### Request

- Method: GET
- URL: /process?git-url={git-url}&branch={branch}
  - `git-url`: git url to the target system.
  - `branch`: tag or branch of the target system.

#### Response

- Body(Json)
  - `time`: Project Runtime.
  - `vul`: Vulnerabilities Detected.
  - `vul_cnt`: Count of the detected vulnerabilities.

#### Docker build

You should fully generate the cache before building the docker.

```bash
docker build .
```

### Notes

The experiments are conducted on a machine with a 3.40 GHz Intel i7-13700k processor and 48 GB of RAM, running on ArchLinux with Linux Zen Kernel. **Please adjust the max process in each component to avoid crashes according to your experiments environments**.

The thresholds provided in `threshold.yml` are based on our findings in preliminary research provided in our paper.


## Supplement to the Paper
For space reasons, some of the content could not be presented in the paper and is written here as an addendum to the paper.

### Investigation of Vulnerability Propagation on all 51,485 C/C++ projects

**Top ten projects with most detected vulnerabilities**
![image](https://github.com/RECOMECODES/RECOME/blob/main/images/1.jpg)

**Top ten widely propagated vulnerability types**
![image](https://github.com/RECOMECODES/RECOME/blob/main/images/2.jpg)

**The CDF distribution of CVSS scores**
![image](https://github.com/RECOMECODES/RECOME/blob/main/images/3.jpg)

**Top ten vulnerabilities with the highest monthly vulnerability proliferation rate**
![image](https://github.com/RECOMECODES/RECOME/blob/main/images/4.jpg)

**Number of vulnerabilities from CVE-2010-0205**
![image](https://github.com/RECOMECODES/RECOME/blob/main/images/5.jpg)

