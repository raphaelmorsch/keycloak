<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header" || section = "show-username">
        <script type="text/javascript">
            function fillAndSubmit(authExecId) {
                document.getElementById('authexec-hidden-input').value = authExecId;
                document.getElementById('kc-select-credential-form').submit();
            }
        </script>
        <#if section = "header">
            ${msg("loginChooseAuthenticator")}
        </#if>
    <#elseif section = "form">

        <form id="kc-select-credential-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="list-group list-view-pf">
                <#list auth.authenticationSelections as authenticationSelection>
                    <div class="list-group-item list-view-pf-stacked">
                        <div class="list-view-pf-main-info" onclick="fillAndSubmit('${authenticationSelection.authExecId}')">
                            <div class="list-view-pf-left">
                                <span class="${authenticationSelection.iconCssClass}"></span>
                            </div>
                            <div class="list-view-pf-body">
                                <div class="list-view-pf-description">
                                    <div class="list-group-item-heading">
                                        ${msg('${authenticationSelection.userDisplayName}')}
                                    </div>
                                    <div class="list-group-item-text">
                                        ${msg('${authenticationSelection.userHelpText}')}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </#list>
                <input type="hidden" id="authexec-hidden-input" name="authenticationExecution" />
            </div>
        </form>

    </#if>
</@layout.registrationLayout>

