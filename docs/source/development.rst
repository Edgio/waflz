Development
-----------

Contributions Discovered in Development
=======================================
In the process of developing waflz, using the `open source modsecurity <https://github.com/SpiderLabs/ModSecurity/>`_ as a reference, several potential issues were discovered in the standard implementation.

* heap overflows:

  * `ip tree: off-by-one on the heap <https://github.com/SpiderLabs/ModSecurity/issues/1793>`_
  * `parse_arguments: off-by-one <https://github.com/SpiderLabs/ModSecurity/issues/1799>`_

* logic issues:

  * `utf8 character detection <https://github.com/SpiderLabs/ModSecurity/issues/1794>`_
  * `query string with slashes <https://github.com/SpiderLabs/ModSecurity/issues/1795>`_

* data mangling:

  * `suricata/snort data mangling <https://github.com/SpiderLabs/ModSecurity/issues/1796>`_

