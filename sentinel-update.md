This file is a merged representation of a subset of the codebase, containing specifically included files and files not matching ignore patterns, combined into a single document by Repomix.

<file_summary>
This section contains a summary of this file.

<purpose>
This file contains a packed representation of a subset of the repository's contents that is considered the most important context.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.
</purpose>

<file_format>
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  - File path as an attribute
  - Full contents of the file
</file_format>

<usage_guidelines>
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.
</usage_guidelines>

<notes>
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Only files matching these patterns are included: *.txt
- Files matching these patterns are excluded: .git/**
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)
</notes>

</file_summary>

<directory_structure>
requirements.txt
</directory_structure>

<files>
This section contains the contents of the repository's files.

<file path="requirements.txt">
# Sentinel Core Dependencies
fastapi>=0.104.0
uvicorn[standard]>=0.24.0
httpx>=0.25.0
aiosqlite>=0.19.0
networkx>=3.2
beautifulsoup4>=4.12.0
python-multipart>=0.0.6
cryptography>=41.0.0
websockets>=12.0
requests>=2.31.0
pytest>=7.4.0
pytest-asyncio>=0.21.0
openai>=1.3.0
</file>

</files>
