<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayWide=false>
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <form id="kc-select-credential-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
          <select name="authenticationExecution" size="1">
                <#list authenticationExecutions as authenticationExecution>
                    <option value="${authenticationExecution.id}">${authenticationExecution.authenticator}</option>
                </#list>
          </select>
          <br><br>
          <input type="submit" name="selectAuthenticator" value = "Select authenticator type">
        </form>
        <br><br>
        <#nested "form">
    </#if>
</@layout.registrationLayout>
</#macro>