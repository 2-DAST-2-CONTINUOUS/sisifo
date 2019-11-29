# Sisifo
Herramienta para entornos de integración continua (CI/CD) para determinar si una aplicación cumple con los mínimos de seguridad antes de desplegarse en un entorno de producción

## Plantillas GitLab CI/CD para análisis dinámico de seguridad

El directorio ci-templates contiene las plantillas de las diferentes herramientas de análisis dinámico, las cuales se podrán importar en el archivo **.gitlab-ci.yml** del repositorio de GitLab para obtener la funcionalidad de análisis de seguridad en el pipeline.

Antes de añadir los diferentes *stages* de análisis dinámico la aplicación a analizar deberá haber sido desplegada, bien en un lugar accesible o en un docker levantado como servicio dentro del flujo de GitLab

### ARACHNI.gitlab-ci.yml

Para incluir el análisis con arachni se deberá importar la plantilla de la siguiente manera

    include:
      - project: 2-dast-2-continuos/templates
      file: ARACHNI.gitlab-ci.yml
      ref: master

Y crear un *stage* del que extenderemos

    arachni:
      extends:
      - .analyze_arachni
    stage:
      arachni

Para lanzar un escaneo con las opciones por defecto tan solo es necesario declarar una variable **AR_URL** que será la url por la que empezará el análisis 

    variables:
      AR_URL: "<URL_APPLICACION>"

El resultado final sería

    include:
      - project: 2-dast-2-continuos/templates
        file: ARACHNI.gitlab-ci.yml
        ref: master
    stages:
      - arachni
    arachni:
      extends:
        - .analyze_arachni
      stage:
        arachni 
      variables:    
        AR_URL: "<URL_APPLICACION>"

Se puede indicar a la herramienta que es necesario realizar login en la aplicación a analizar declarando las siguientes variables:

* AR_LOGIN_URL -> Url en la que se realiza el login
* AR_LOGIN_PARAMS -> Parámetros del login en el siguiente formato "param1=value1&param2=value2"
* AR_CHECK_LOGIN_SUCCESS -> Texto a buscar si el login ha sido satisfactorio
* AR_LOGOUT_PATTERN -> Patron del endpoint de logout para excluirlo del alcance del análisis

#### Personalización del análisis 

Declarando la variable **AR_CHECKS** se puede definir que tipo de comprobaciones se van a realizar. El formato de esta variable coincide con el del parámetro *--checks* de la herramienta Arachni.

La lista de las diferentes comprobaciones es:

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

Para más información se puede consultar la documentación oficial: https://github.com/Arachni/arachni/wiki/Command-line-user-interface#checks-checks_example

### ZAP.gitlab-ci.yml

Para incluir el análisis con arachni se deberá importar la plantilla de la siguiente manera

    include:
      - project: 2-dast-2-continuos/templates
      file: ZAP.gitlab-ci.yml
      ref: master

Y crear un *stage* del que extenderemos

    zap:
      extends:
        - .analyze_zap
      stage:
        zap

Para lanzar un escaneo con las opciones por defecto tan solo es necesario declarar una variable **ZAP_WEBSITE** que será la url por la que empezará el análisis 

    variables:
      ZAP_WEBSITE: "<URL_APPLICACION>"

El resultado final sería

    include:
      - project: 2-dast-2-continuos/templates
      file: ZAP.gitlab-ci.yml
      ref: master
    zap:
      extends:
      - .analyze_zap
      variables:
        ZAP_WEBSITE: <URL_APPLICACION>
      stage: zap

Se puede indicar a la herramienta que es necesario realizar login en la aplicación a analizar declarando las siguientes variables:

* ZAP_AUTH_URL -> Url en la que se realiza el login
* ZAP_USERNAME -> Nombre de usuario
* ZAP_PASSWORD -> Contraseña
* ZAP_USERNAME_FIELD -> Valor del parámetro *name* del *input* del nombre de usuario
* ZAP_PASSWORD_FIELD -> Valor del parámetro *name* del *input* de la contraseña
* ZAP_AUTH_EXCLUDE_URLS -> Patron del endpoint de logout para excluirlo del alcance del análisis
