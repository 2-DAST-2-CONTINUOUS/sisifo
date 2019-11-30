## Sisifo CI/CD template for Dynamic Security Analysis

This template is a docker container registered in 2 DAST 2 Continuous GitLab Repository.

- **Sisifo** - [GitLab Link](https://gitlab.com/2-dast-2-continuos/sisifo)


The sisifo directory contains the templates of the different dynamic analysis tools, which can be imported into the file **.gitlab-ci.yml** from the GitLab repository to obtain the security analysis functionality in the pipeline.

Before adding the different dynamic analysis *stages* the application to be analyzed must have been deployed, either in an accessible place or in a docker raised as a service within the GitLab flow.

### ARACHNI.gitlab-ci.yml

To include the analysis with arachni the template must be imported as follows
```
    include:
      - project: 2-dast-2-continuous/templates
      file: ARACHNI.gitlab-ci.yml
      ref: master
```     

And create a *stage* that we'll extend
```
    arachni:
      extends:
      - .analyze_arachni
    stage:
      arachni
```
To launch a scan with the default options you just need to declare a variable **AR_URL** which will be the url that the analysis will start with. 
```
    variables:
      AR_URL: "<URL_APPLICATION>"
```
The final result would be
```
    include:
      - project: 2-dast-2-continuous/templates
        file: ARACHNI.gitlab-ci.yml
        ref: master
    stages
      - arachni
    arachni:
      extends:
        - .analyze_arachni
      stage:
        arachni 
      variables:    
        AR_URL: "<URL_APPLICATION>"
```
You can indicate to the tool that it is necessary to login to the application to be analyzed by declaring the following variables:

* AR_LOGIN_URL -> Url in which the login is made
* AR_LOGIN_PARAMS -> Login parameters in the following format "param1=value1&param2=value2".
* AR_CHECK_LOGIN_SUCCESS -> Text to search if the login has been successful
* AR_LOGOUT_PATTERN -> Logout endpoint pattern to exclude it from the scope of analysis

#### Personalization of the analysis 

Declaring the variable **AR_CHECKS** it is possible to define the type of checks to be carried out. The format of this variable coincides with that of parameter *--checks* of the Arachni tool.

The list of the different checks is:

* insecure_cross_domain_policy_headers
* xst
* insecure_cross_domain_policy_access
* localstart_asp
* common_admin_interfaces
* common_directories
* allowed_methods
* http_only_cookies
* captcha
* cvs_svn_users
* password_autocomplete
* mixed_resource
* cookie_set_for_parent_domain
* unencrypted_password_forms
* private_ip
* form_upload
* x_frame_options
* hsts
* emails
* insecure_cookies
* credit_card
* ssn
* insecure_cors_policy
* html_objects
* htaccess_limit
* interesting_responses
* origin_spoof_access_restriction_bypass
* backup_files
* http_put
* directory_listing
* webdav
* backdoors
* insecure_client_access_policy
* backup_directories
* common_files
* xpath_injection
* xss_script_context
* xss_dom
* no_sql_injection_differential
* trainer
* ldap_injection
* code_injection
* file_inclusion
* session_fixation
* xss_event
* code_injection_php_input_wrapper
* rfi
* xss_path
* sql_injection
* unvalidated_redirect
* xss
* no_sql_injection
* sql_injection_differential
* csrf
* os_cmd_injection_timing
* path_traversal
* code_injection_timing
* xss_tag
* response_splitting
* source_code_disclosure
* unvalidated_redirect_dom
* xss_dom_script_context
* sql_injection_timing
* xxe
* os_cmd_injection

For further information, please consult the official documentation: https://github.com/Arachni/arachni/wiki/Command-line-user-interface#checks-checks_example

### ZAP.gitlab-ci.yml

To include the analysis with arachni the template must be imported as follows
```
    include:
      - project: 2-dast-2-continuous/templates
      file: ZAP.gitlab-ci.yml
      ref: master
```
And create a *stage* that we'll extend
```
    zap
      extends:
        - .analyze_zap
      stage:
        zap
```
To launch a scan with the default options it is only necessary to declare a variable **ZAP_WEBSITE** that will be the url where the analysis will start. 
```
    variables:
      ZAP_WEBSITE: "<URL_APPLICATION>"
```
The final result would be
```
    include:
      - project: 2-dast-2-continuous/templates
      file: ZAP.gitlab-ci.yml
      ref: master
    zap
      extends:
      - .analyze_zap
      variables:
        ZAP_WEBSITE: <URL_APPLICATION>
      stage: zap
```
You can indicate to the tool that it is necessary to login to the application to be analyzed by declaring the following variables:

* ZAP_AUTH_URL -> Url in which the login is made
* ZAP_USERNAME -> User name
* ZAP_PASSWORD -> Password
* ZAP_USERNAME_FIELD -> Value of parameter *name* of *input* of user name
* ZAP_PASSWORD_FIELD -> Parameter value *name* of *input* of password
* ZAP_AUTH_EXCLUDE_URLS -> Logout endpoint pattern to exclude it from the scope of analysis
