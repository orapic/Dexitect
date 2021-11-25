# Dexitect
## Introduction
Dexitect performs diffing of APK files based on the Simhash algorithm and similarity distance scoring method. Uses the Androguard framework in order to extract the information from the dex files.

What does it do?
* Diffing of classes found in `classes.dex` files.
* Generates output txt files for an easier `grep`.
* Generates an HTML report.

Output format is like the following:
```
<Class in apk1> <Class(es) in apk2> <Similarity Score>
````
The score goes from 0 to 1.0, where 1.0 indicates two identical files.

## Usage
Example usage:
```
python3 dexitect.py -f excluded_packages.txt "../path1/apk1.apk" "../path2/apk2.apk"
```
All the output files (manifest, dex, jars, etc...) will be saved in the `output/<timestamp>` folder.

Options:
```
  -h, --help         show this help message and exit
  --excpkgs EXCPKGS  Packages names (string) separated by semicolons being
                     excluded in the comparison for better performance (watch
                     out for obfuscation). Example: --excpkgs="com/google/andr
                     oid/;android/support/;androidx/"
  -f F               Txt file where excluded packages are located. One package
                     per line.
  -o                 If the apks are name obfuscated. (not in use yet)
  -k K               Hamming distance used for bulk comparison (default=3).
  -t T               Threshold for candidates during accute comparison
                     (default=0.8).
```
## Sample Output
### HTML Report
Index:
[index html](images/index.png)
Similar results:
[similar html](images/similar_results.png)

### TXT Report
```
Analysis of ../../apks/zentangle/Zentangle Mosaic_v1.2_apkpure.com.apk done in: 0:00:09.742237
Analysis of ../../apks/zentangle/Zentangle v1.2 sub_mod_mobilisim.apk done in: 0:00:13.826553
Simhashing of the ../../apks/zentangle/Zentangle Mosaic_v1.2_apkpure.com.apk done in: 0:00:07.009787
Comparison made with a hamming distance of: 3
Simhashing of the ../../apks/zentangle/Zentangle v1.2 sub_mod_mobilisim.apk done in: 0:00:06.128403
Duplicate search done in:0:00:42.486202
Number of classes analysed in apk1: 2137
Number of classes analysed in apk2: 2139
Number of classes which do not have near duplicates: 307
Class which name is not present in the candidates list: 157
Average number of duplicates for classes with candidates: 3.550273224043716

*** Comparison reuslts ***
* Similar classes (1830)*
FORMAT : Class 1 in apk1 -> Candidates with highest similarity score in apk2
La/a/a/a/a; -> La/a/a/a/a; | 1.0
La/a/a/a/b$a; -> La/a/a/a/b$a; | 1.0
La/a/a/a/b$c; -> La/a/a/a/b$c; | 1.0
La/a/a/a/b; -> La/a/a/a/b; | 1.0
Lb/a/j; -> Lb/a/j; | 1.0
Lb/a/k/a/a$a; -> Lb/a/k/a/a$a; | 1.0
Lb/a/k/a/a; -> Lb/a/k/a/a; | 1.0
Lb/a/l/a/a$f; -> Lb/a/l/a/a$f; | 1.0
Lb/a/l/a/a$g; -> Lb/a/l/a/a$g; | 1.0
Lb/a/l/a/b$a; -> Lb/a/l/a/b$a; | 1.0
[...]
```
## Installation
Dexitect uses a modified version of 1eong implementation of Simhash (the original project can be found [here](https://github.com/1e0ng/simhash)). As soon as the PR on the project is finished, it will be usable to everybody.

## Credits:
* Androguard: [Androguard Github Repository](https://github.com/androguard/androguard)
* 1e0ng's Python Simhash implementation: [1e0ng Github Repository](https://github.com/1e0ng/simhash )
* Simhash alogrithm: [Simhash Algorithm Paper](https://www.cs.princeton.edu/courses/archive/spr04/cos598B/bib/CharikarEstim.pdf)
* Implementation based on Quarkslab post: [Quarkslab Article](https://blog.quarkslab.com/android-application-diffing-engine-overview.html)
* 0xjet for his support: [0xjet Github Repository](https://github.com/0xjet)
