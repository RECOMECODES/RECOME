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

### The detailed description of three importance calculation methods.
Random Forest is a machine learning method that constructs multiple decision trees for classification or regression. 
It excels not only in classification tasks but also in providing interpretability by outputting feature importance. 
This offers a straightforward and intuitive means to interpret the model, making it a common method for importance calculation.
Distance Correlation and Maximal Information Coefficient are common statistical measures used to quantify the relationship between two variables.
They are used to assess the extent to which the occurrence of one random event influences the probability of another random event. 
When one event is the target variable, a stronger correlation between features and the target variable indicates higher feature importance. 
Distance Correlation and Maximal Information Coefficient exhibit a certain level of robustness, being relatively less affected by outliers and noise, thus offering resilience against anomalies in the data to some extent. 
Therefore, we choose these three methods to compute the importance of the 18 metrics.

### The detailed description of three correlation calculation methods.
Distance Correlation is a common non-parametric method for measuring the correlation between two variables. 
It is defined by projecting the original data into a high-dimensional space and then computing the correlation between the Euclidean distances of data points and distances in the high-dimensional space.
It utilizes the distance matrix between samples to calculate the distance correlation coefficient, regardless of the distribution form of the original data.
Spearman-Rank Correlation and Kendall-tau Correlation are also non-parametric methods used to measure the correlation between two variables. 
They are calculated based on the ranks of variables rather than the numerical values of the original data, thus requiring no assumptions about the distribution of the data. 
These three methods are robust, meaning they can provide reliable estimates of correlation even when the data does not follow a normal distribution.


### The result of three correlation calculation methods.
![The Spearman correlations between 14 code metrics](https://github.com/RECOMECODES/RECOME/blob/main/images/Spearman.png)
![The Distance correlations between 14 code metrics](https://github.com/RECOMECODES/RECOME/blob/main/images/Distance.png)
![The Kendall correlations between 14 code metrics](https://github.com/RECOMECODES/RECOME/blob/main/images/Kendall.png)


### All 20 expression types.

| Expression Type               | Description                                                                                                                                                   |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| binary\_expression            | An expression composed of two operands and an operator\.                                                                                                      |
| call\_expression              | An expression for calling a function or method, including the function name and arguments\.                                                                   |
| parenthesized\_expression     | An expression enclosed in parentheses to control evaluation order or change precedence\.                                                                      |
| cast\_expression              | An expression for converting one data type to another\.                                                                                                       |
| pointer\_expression           | An expression involving pointers, such as address\-of or dereference operations\.                                                                             |
| sizeof\_expression            | An expression that returns the size in bytes of an object or data type\.                                                                                      |
| comma\_expression             | An expression containing multiple expressions separated by commas, evaluated left to right\.                                                                  |
| assignment\_expression        | An expression for assigning a value to a variable or object\.                                                                                                 |
| field\_expression             | An expression for accessing member fields of a struct or class\.                                                                                              |
| new\_expression               | An expression for dynamically allocating memory and creating objects\.                                                                                        |
| unary\_expression             | An expression composed of a single operand and an operator\.                                                                                                  |
| update\_expression            | An expression for incrementing or decrementing variables\.                                                                                                    |
| subscript\_expression         | An expression for accessing elements of arrays, vectors, or other sequence types\.                                                                            |
| delete\_expression            | An expression for releasing dynamically allocated memory\.                                                                                                    |
| conditional\_expression       | An expression that selects between two expressions based on a condition, similar to the ternary operator\.                                                    |
| offsetof\_expression          | An expression that returns the offset of a member within a struct or class\.                                                                                  |
| compound\_literal\_expression | An expression for creating compound literals, commonly used in C\.                                                                                            |
| alignof\_expression           | An expression that returns the alignment requirement of an object or data type\.                                                                              |
| gnu\_asm\_expression          | An expression embedding GNU assembly code, commonly used in C and C\+\+\.                                                                                     |
| lambda\_expression            | An expression for creating anonymous functions, typically used in functional programming languages or languages supporting functional programming paradigms\. |


### Vulnerability Types.
We analyzed 147 vulnerabilities detected by RECOME. We found that the majority of the vulnerabilities fall into the following six categories. 
For instance, there are 35 Buffer Overflow vulnerabilities (CWE-119), 26 Improper Input Validation vulnerabilities (CWE-20), 14 Integer Overflow or Wraparound vulnerabilities (CWE-190), 12 Null Pointer Dereference vulnerabilities (CWE-476), 11 Out-of-bounds Read vulnerabilities (CWE-125), and 10 Out-of-bounds Write vulnerabilities (CWE-787). 
This indicates that RECOME is more proficient at detecting these six types of vulnerabilities, while it pays less attention to other types of vulnerabilities, such as CWE-399, CWE-834, CWE-434, CWE-362, and CWE-754.
There are three possible reasons for this phenomenon.
Firstly, the metrics we selected might lead to a bias towards certain types of vulnerabilities. 
Using LOC for filtering might favor complexly constructed vulnerabilities, potentially missing those that can be triggered with fewer lines of code. 
Using NEXP might bias towards vulnerabilities related to expressions, ignoring those unrelated to expressions.
For example, the _"sizeof"_ and _"pointer"_ expressions focus more on buffer size and pointer usage, allowing RECOME to proficiently detect out-of-bounds read and write vulnerabilities.
Conversely, CWE-362 is caused by the shared resource being modified by another code sequence operating concurrently, which is unrelated to a single expression, thus RECOME is not adept at detecting CWE-362 vulnerabilities.
Additionally, since RECOME is a tool for detecting recurring vulnerabilities, the types of vulnerabilities it detects can also be influenced by the dataset. Expanding the dataset could encompass a broader range of vulnerability types.
Lastly, common vulnerabilities like CWE-20 and CWE-787 are prevalent in real-world applications, which may explain RECOME's higher detection count.

### False Positive Analysis for VUDDY and MOVERY.
Most of the false positives generated by VUDDY are caused by abstraction. 
When a vulnerability can be fixed by simply changing the abstracted part, the abstracted repaired security function and the vulnerable function will have identical hash values.
This reason leads to widespread false positives of VUDDY. 
Although our method also utilizes abstraction and may consider repaired security functions as potential vulnerabilities, we prevent such false positives by conducting line deletion checks and metrics distance checks. 
Most of the false positives generated by MOVERY are also due to our second reason for false positives. 
Since MOVERY does not further limit the matching quantity, it produces more false positives than our tool. 
Additionally, MOVERY also generates false positives due to the application of abstraction.

### False Negative Analysis for VUDDY and MOVERY.
The use of precise matching after abstraction may cause VUDDY to miss changes that do not affect vulnerability triggering, resulting in a large number of false negatives. 
The use of deleted and added lines of MOVERY leads to false negatives for the same reason as RECOME. 
Moreover, The lack of counting added lines results in more false negatives in MOVERY compared to our method.


