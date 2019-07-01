[![Build Status](https://travis-ci.org/aquasecurity/bench-common.svg?branch=master)](https://travis-ci.org/aquasecurity/bench-common)
# Build and Test
## Requirement
1. Docker CE
1. Docker Compose

## Run
1. go build
1. docker-compose up

## Alternatively
1. go build
1. docker build -t aquasecurity/app-bench .
1. docker run -it aquasecurity/app-bench



## Test config YAML representation
#####Example Yaml File
```
id: " "
description: Custom Checks
groups:
  - id: 1
    description: Check netcat
    checks:
      - id: 1.1
        description: "Check netcat"        
        action:
          count: true
          type: FileSearch
          args:
            path: "/"
            searchTerm: "nc"
            searchType: "exact"
        
        tests:
          bin_op: and
          test_items:
            - flag: "0"
              compare:
                op: eq
                value: "0"
              set: true
        remediation: "uninstall  netcat"
        scored: true
  - id: 2
    description: Test 1
    checks:
      - id: 1.1
        description: "Check sshd"
        action:
          count: true
          type: FileSearch
          args:
            path: "/"
            searchTerm: "sshd"
            searchType: "exact"
        tests:
          bin_op: and
          test_items:
            - flag: "0"
              compare:
                op: eq
                value: "0"
              set: true
        remediation: "uninstall  sshd"
        scored: true
  - id: 3
    description: Check World files
    checks:
      - id: 1.1
        description: "Check World files"
        action:
          count: true
          type: FileSearch
          args:
            path: "/"
            perm: 777
        tests:
          bin_op: and
          test_items:
            - flag: "0"
              compare:
                op: eq
                value: "0"
              set: true
        remediation: "remove world files"
        scored: true
``` 

The yaml document is composed of a group of tests, where the test is a logical unit called "checks".
Each "check" might contain one or more  test blocks.
The main elements of each "checks" block are "action" and "tests"

#####Action

'action' block defines certain operation to be executed on target host or image, this block consist of three general entities:   
1. **type**  - defines particular operation TextSearch or FileSearch
2. **count** - accepts boolean true/false and defines the designate the output format, when it false it produces a textual output and        
           when it true, it returns the amount of lines found in the output.
3. **args**      - this block consist of several entities with general purpose to define the variety of filtering operations.  
3.1 **path**        - inner image or host file system path, used as a start point for required operation   
3.2 **searchTerm**  - defines the 'search term'    
3.3 **searchType**  - defines the 'search term pattern', can be one of following:  **exact**, **hasPrefix**, **hasSuffix**, **contains**   
3.4 **groupId**  - numeric User Id  
3.4 **userId**   - numeric Group Id    
3.4 **perm**     - defines the file permission criteria in octal format i.e. 777 or -4000  ('-' and '/' prefix  can be used similar to linux 'find -perm' option)    
    
