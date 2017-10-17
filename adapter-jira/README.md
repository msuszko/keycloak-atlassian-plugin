Keycloak adapters for Atlassian Jira
========================================

Open Source SSO adapters to connect Atlassian Jira with Keycloak or other OpenID Connect compatible IdM server.

Installation
------------
Copy all adapter jar files into `$JIRA_HOME/atlassian-jira/WEB-INF/lib`

Edit file `$JIRA_HOME/atlassian-jira/WEB-INF/classes/seraph-config.xml` change `<authenticator class="com.atlassian.jira.security.login.JiraSeraphAuthenticator"/>` to `<authenticator class="org.keycloak.adapters.atlassian.jira.OIDCKeycloakJiraAuthenticator"/>` 

Edit file `$JIRA_HOME/atlassian-jira/WEB-INF/web.xml`, add OIDC filter in these two steps:
* add new filter definition (can be last afer other filters):   

``` xml
    <filter>
      <filter-name>KeycloakOIDCJiraFilter</filter-name>
      <filter-class>org.keycloak.adapters.atlassian.jira.KeycloakOIDCJiraFilter</filter-class>
    </filter>
```

* add filter mapping of this filter just after filter mapping of `encoding` filter:
    
``` xml
    <filter-mapping>
       <filter-name>KeycloakOIDCJiraFilter</filter-name>
       <url-pattern>/*</url-pattern>
    </filter-mapping>
```
* TODO configure OIDC adapter



License
-------

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)