# burpsuite-sitemap-export-to-filesystem
Exports an XML sitemap to a user-specified folder, maintaining directory structure of the application for easier analysis. 

Fixes the issue of dumping every single request into one massive XML file which can be hard for a lot of tools to deal with, particularly LLMs.

Usage:

Click the top of the sitemap tree in Burp (the entry with the actual domain/hostname - highest level of the tree) in your Target tab. Right click -> "Save selected items" -> Tick "Base64-encode requests and responses" -> Save as your_app.xml.

Then:

```
python3 extract-sitemap.py your_app.xml /path/to/folder/you/want/to/export/into
```

Your application should have been exported to your target folder and the script will have preserved and recreated the path structure exactly as the application you were testing had.
