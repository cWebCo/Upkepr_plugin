=== Upkepr Mintenance===
Contributors: WebGarh Solutions
Tags: wordpress maintenance, wordpress information
Requires at least: 4.9
Tested up to: 6.1.1
Requires PHP: 5.6
Stable tag: 1.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

The best WordPress plugin to get inforation about wordpress core, plugins and themes by rest apis

== Description ==


Upkepr Maintainance plugin is providing information about wordpress site health. It will show the information of core wordpress, plugins and themes.
It has 5 apis.

## Note: Validation key is auto generate on wordpress site on Activtion of the plugin. This validation key and domain name (base domain where wordpress installed ) is used for authentication.

1. {domainname}/wp-json/upkepr-isKeyValid/key /* to check if key is valide */
header 
i. content type: json
ii. "Upkeprvalidationkey": {vaidation key}
iii. "Upkeprvalidationdomain": {base domainname}


2. {domainname}/wp-json/upkepr-is_keydomainusername_valid/data /* to check if key, domain and username is valide */
header 
i. content type: json
ii. "Upkeprvalidationkey": {vaidation key}
iii. "Upkeprvalidationdomain": {base domainname}
body
i. "username": {Username or Email of the user} 


3. {domainname}/wp-json/upkepr-wpinfo/wpinfo /* to get wp infomation data */
header 
i. content type: json
ii. "Upkeprvalidationkey": {vaidation key}
iii. "Upkeprvalidationdomain": {base domainname}
body
i. "username": {Username or Email of the user} 

4. {domainname}/wp-json/upkepr-gettoken/byusername  /* to get token */
header 
i. content type: json
ii. "Upkeprvalidationkey": {vaidation key}
iii. "Upkeprvalidationdomain": {base domainname}
body
i. "username": {Username or Email of the user} 


5. {domainname}/wp-json/upkepr-getloginurl/byusername /* to get login url */
header 
i. content type: json
ii. "Upkeprvalidationkey": {vaidation key}
iii. "Upkeprvalidationdomain": {base domainname}
iv. Authorization token: {bearer token}
body
i. "username": {Username or Email of the user}
