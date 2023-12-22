

# Exe Encryptor

## Function
This is an executable encryptor. It does the following:
Compress and encrypt each section.
Destroy relocation table and
Add another section in the end to recover Relocation Table.
Dynamically load IAT with code obfuscation.


## Idea
The main idea idea was to :
first move the relocation table down, 
delete the relocation table in PE head,
fix the relocation table manually & edit IAT with assembly code obfuscation 
by self-made assembly code
in ollyDbg at the program entry point,
so no function name will be shown explicitely in reverse engineering software such as OllyDbg.

## Before

### Relocation table

![Capture](/Image/Capture1.JPG)

![Capture](/Image/Capture.JPG)

###  Section table

![Capture4](/Image/Capture4.JPG)

## After

###  Relocation table

![Capture3](/Image/Capture2.JPG)

![Capture3](/Image/Capture3.JPG)

###  Section table

![Capture5](/Image/Capture5.JPG)

![Capture6](/Image/Capture6.JPG)

