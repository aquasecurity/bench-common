The CIS Benchmark recommends configurations to harden various 
components, including Docker, Kubernetes, Linux, etc... 
These recommendations are usually configuration options, and can be 
specified by flags to binaries programs, or in configuration files.

The Benchmark also provides commands to audit an installation, identify
places where the security can be improved, and steps to remediate these
identified problems.

# Test and config files

A typical `*-bench` project runs checks specified in `controls` files that are a YAML 
representation of the CIS Benchmark checks. There is a 
`controls` file per version and node type.

`controls` for the various versions of the benchmark can be found in directories
with same name as the CIS versions under `cfg/`, for example `cfg/cis-1.4.0`.

## Controls

`controls` is a YAML document containing the test definitions for a benchmark.

`controls` is the fundamental input to a `*-bench` project. The following is a Kubernetes CIS Benchmark example 
of `controls`:

```yml
---
controls:
id: 1
text: "Master Node Security Configuration"
type: "master"
groups:
- id: 1.1
  text: API Server
  checks:
    - id: 1.1.1
      text: "Ensure that the --allow-privileged argument is set (Scored)"
      audit: "ps -ef | grep kube-apiserver | grep -v grep"
      tests:
      bin_op: or
      test_items:
      - flag: "--allow-privileged"
        set: true
      - flag: "--some-other-flag"
        set: false
      remediation: "Edit the /etc/kubernetes/config file on the master node and
        set the KUBE_ALLOW_PRIV parameter to '--allow-privileged=false'"
      scored: true
- id: 1.2
  text: Scheduler
  checks:
    - id: 1.2.1
      text: "Ensure that the --profiling argument is set to false (Scored)"
      audit: "ps -ef | grep kube-scheduler | grep -v grep"
      tests:
        bin_op: or
        test_items:
          - flag: "--profiling"
            set: true
          - flag: "--some-other-flag"
            set: false
      remediation: "Edit the /etc/kubernetes/config file on the master node and
        set the KUBE_ALLOW_PRIV parameter to '--allow-privileged=false'"
      scored: true
```

`controls` is composed of a hierarchy of groups, sub-groups and checks. Each of
the `controls` components have an id and a text description which are displayed 
in the `*-bench` project output.

`type` specifies the type a `controls` is for.

## Groups

`groups` is list of subgroups which test the various Kubernetes components
that run on the node type specified in the `controls`. 


These subgroups have `id`, `text` fields which serve the same purposes described
in the previous paragraphs. The most important part of the subgroup is the
`checks` field which is the collection of actual `check`s that form the subgroup.

This is an example of a subgroup and checks in the subgroup.

```yml
id: 1.1
text: API Server
checks:
  - id: 1.1.1
    text: "Ensure that the --allow-privileged argument is set (Scored)"
    audit: "ps -ef | grep kube-apiserver | grep -v grep"
    tests:
    # ...
  - id: 1.1.2
    text: "Ensure that the --anonymous-auth argument is set to false (Not Scored)"
    audit: "ps -ef | grep kube-apiserver | grep -v grep"
    tests:
    # ...
``` 

The `*-bench` project supports running a subgroup by specifying the subgroup `id` on the
command line, with the flag `--group` or `-g`.

## Check

In a `*-bench` project , a `check` object embodies a recommendation from the CIS benchmark.  This an example
`check` object:

```yml
id: 1.1.1
text: "Ensure that the --anonymous-auth argument is set to false (Not Scored)"
audit: "ps -ef | grep kube-apiserver | grep -v grep"
tests:
  test_items:
  - flag: "--anonymous-auth"
    compare:
      op: eq
      value: false
    set: true
remediation: |
  Edit the API server pod specification file kube-apiserver
  on the master node and set the below parameter.
  --anonymous-auth=false
scored: false
```

A `check` object has an `id`, a `text`, an `audit`, a `tests`, `remediation`
and `scored` fields.

The `*-bench` project supports running individual checks by specifying the check's `id`
as a comma-delimited list on the command line with the `--check` flag.

The `audit` field specifies the command to run for a check. The output of this
command is then evaluated for conformance with the CIS Kubernetes Benchmark
recommendation.

The audit is evaluated against a criteria specified by the `tests`
object. `tests` contain `bin_op` and `test_items`.

`test_items` specify the criteria(s) the `audit` command's output should meet to
pass a check. This criteria is made up of keywords extracted from the output of
the `audit` command and operations that compare these keywords against
values expected by the CIS Benchmark. 

There are two ways to extract keywords from the output of the `audit` command,
`flag` and `path`.

`flag` is used when the keyword is a command line flag. The associated `audit`
command is usually a `ps` command and a `grep` for the binary whose flag we are
checking:

```sh
ps -ef | grep somebinary | grep -v grep
``` 

Here is an example usage of the `flag` option:

```yml
# ...
audit: "ps -ef | grep kube-apiserver | grep -v grep"
tests:
  test_items:
  - flag: "--anonymous-auth"
  # ...
```

`path` is used when the keyword is an option set in a JSON or YAML config file.
The associated `audit` command is usually `cat /path/to/config-yaml-or-json`.
For example:

```yml
# ...
text: "Ensure that the --anonymous-auth argument is set to false (Not Scored)"
audit: "cat /path/to/some/config"
tests:
  test_items:
  - path: "{.someoption.value}"
    # ...
```

`test_item` compares the output of the audit command and keywords using the
`set` and `compare` fields.

```yml
  test_items:
  - flag: "--anonymous-auth"
    compare:
      op: eq
      value: false
    set: true
```

`set` checks if a keyword is present in the output of the audit command or in
a config file. The possible values for `set` are true and false.

If `set` is true, the check passes only if the keyword is present in the output
of the audit command, or config file. If `set` is false, the check passes only
if the keyword is not present in the output of the audit command, or config file.

`compare` has two fields `op` and `value` to compare keywords with expected
value. `op` specifies which operation is used for the comparison, and `value`
specifies the value to compare against.

> To use `compare`, `set` must true. The comparison will be ignored if `set` is
> false

The `op` (operations) currently supported in The `*-bench` project are:
- `eq`: tests if the keyword is equal to the compared value.
- `noteq`: tests if the keyword is unequal to the compared value.
- `gt`: tests if the keyword is greater than the compared value.
- `gte`: tests if the keyword is greater than or equal to the compared value.
- `lt`: tests if the keyword is less than the compared value.
- `lte`: tests if the keyword is less than or equal to the compared value.
- `has`: tests if the keyword contains the compared value.
- `nothave`: tests if the keyword does not contain the compared value.
- `valid_elements`: tests if the keyword contains valid elements from the list of values provided.
  The values in the list provided uses a `,`  as a separator.
- `regex`: tests if the flag value matches the compared value regular expression.
   When defining regular expressions in YAML it is generally easier to wrap them in
   single quotes, for example `'^[abc]$'`, to avoid issues with string escaping.

## Configuration and Variables

Ccomponent configuration and binary file locations and names 
vary based on cluster deployment methods, Operating Systems, and Kubernetes distribution used.
For this reason, the locations of these binaries and config files are configurable
by editing the `cfg/config.yaml` file and these binaries and files can be
referenced in a `controls` file via variables.

The `cfg/config.yaml` file is a global configuration file. Configuration files
can be created for specific CIS versions. Values in the
version specific config overwrite similar values in `cfg/config.yaml`.

For specific ways to overwrite the config values, check the `docs/README.md` for 
corresponding `*-bench` project.
