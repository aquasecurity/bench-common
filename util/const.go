// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package util

type State string
type PermissionSearchMode int

const (
	_           PermissionSearchMode = iota // ignore 0 ...
	ModeExact   PermissionSearchMode = iota //exact match
	ModeAllBits PermissionSearchMode = iota //all permission bits are set for the file
	ModeAnyBits PermissionSearchMode = iota //any permissions are set for the file
)

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL = "FAIL"
	// WARN could not carry out check.
	WARN = "WARN"
	// INFO informational message
	INFO = "INFO"
)

type TextFilterType int32
type FileFilterType int32
type YamlEntityName string
type YamlEntityValue string

const TEXTSEARCH = "TextSearch"
const FILESEARCH = "FileSearch"

const (
	_                   TextFilterType = iota // ignore 0
	TextFilterExact     TextFilterType = iota
	TextFilterContains  TextFilterType = iota
	TextFilterHasPrefix TextFilterType = iota
	TextFilterHasSuffix TextFilterType = iota
)

const (
	_                     FileFilterType = iota // ignore 0
	FileFilterDirectory   FileFilterType = iota
	FileFilterSymblink    FileFilterType = iota
	FileFilterRegularFile FileFilterType = iota
	FileFilterAll         FileFilterType = iota
)

const (
	DirectoryVal YamlEntityValue = "directory"
	SymblinkVal  YamlEntityValue = "symblink"
	FileVal      YamlEntityValue = "file"
	ExactVal     YamlEntityValue = "exact"
	HasPrefixVal YamlEntityValue = "hasPrefix"
	HasSuffixVal YamlEntityValue = "hasSuffix"
	ContainsVal  YamlEntityValue = "contains"
)

const (
	PathEntity       YamlEntityName = "path"
	FilterEntity     YamlEntityName = "searchTerm"
	PermissionEntity YamlEntityName = "perm"
	FileTypeEntity   YamlEntityName = "fileType"
	FilterTypeEntity YamlEntityName = "searchType"
	FilterGroupId    YamlEntityName = "groupId"
	FilterUserId     YamlEntityName = "userId"
)
