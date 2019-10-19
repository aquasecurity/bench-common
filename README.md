[![Build Status](https://travis-ci.org/aquasecurity/bench-common.svg?branch=master)](https://travis-ci.org/aquasecurity/bench-common)
[![Coverage Status][cov-img]][cov]

[cov-img]: https://codecov.io/github/aquasecurity/bench-common/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/bench-common

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

# License
bench-common is licensed under the Apache License 2.0[https://github.com/aquasecurity/bench-common/blob/master/LICENSE]
