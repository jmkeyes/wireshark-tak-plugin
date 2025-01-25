Wireshark TAK Plugin
====================

Dissect TAK / Cursor-on-Target messages within Wireshark.

Getting Started
---------------

  1. Copy [`tak.lua`](tak.lua) into your Wireshark [plugins directory][1].
  2. Download the [TAK Protobuf files][2] to a directory in the Protobuf plugin search path.
  3. Start or reload Wireshark to enable the plugin.

[1]: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html
[2]: https://github.com/deptofdefense/AndroidTacticalAssaultKit-CIV/tree/main/commoncommo/core/impl/protobuf

Notes
-----

  - Package the plugin within a ZIP archive for ease of installation.
  - Use GitHub actions to build a ZIP archive of the TAK protobuf files.
  - Build a native dissector and contribute it to Wireshark.

Contributing
------------

  1. Clone this repository.
  2. Create your branch: `git checkout -b feature/branch`
  3. Commit your changes: `git commit -am "I am developer."`
  4. Push your changes: `git push origin feature/branch`
  5. Create a PR of your branch against the `master` branch.
