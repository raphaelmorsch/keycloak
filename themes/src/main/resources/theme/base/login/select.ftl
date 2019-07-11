<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayWide=false>
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        <script type="text/javascript">
            // Fill up the two hidden and submit the form
            function fillAndSubmit() {
                var selectValue = document.getElementById('authenticators-choice').value;
                if (selectValue != '') {
                    var split = selectValue.split("|");
                    document.getElementById('type-hidden-input').value = split[0];
                    document.getElementById('id-hidden-input').value = split[1];
                    document.getElementById('kc-select-credential-form').submit();
                }
            }

            // We bind the action to the select
            window.addEventListener('load', function() {
                document.getElementById('authenticators-choice').addEventListener('change', fillAndSubmit);
            });
        </script>
        <#nested "header">
    <#elseif section = "form">
        <form id="kc-select-credential-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
          <select id="authenticators-choice" size="1">
                <#list authenticationExecutions as authenticationExecution, credentialModels>
                    <#if credentialModels?has_content>
                         <#list credentialModels as credentialModel>
                                <option value="${authenticationExecution.id}|${credentialModel.id}" <#if selectedCredential?has_content && credentialModel.id == selectedCredential>selected</#if>>${msg('${authenticationExecution.authenticator}')} - <#if credentialModel.userLabel?has_content>${credentialModel.userLabel}<#else>${credentialModel.id}</#if></option>
                         </#list>
                    <#else >
                        <option value="${authenticationExecution.id}|" <#if !(selectedCredential?has_content) && authenticationExecution.id == execution>selected</#if>>${msg('${authenticationExecution.authenticator}')}</option>
                    </#if>
                </#list>
          </select>
          <input type="hidden" id="type-hidden-input" name="authenticationExecution" />
          <input type="hidden" id="id-hidden-input" name="credentialId" <#if selectedCredential?has_content>value="${selectedCredential}"</#if>/>
        </form>
        <br><br>
        <#nested "form">
    </#if>
</@layout.registrationLayout>
</#macro>
