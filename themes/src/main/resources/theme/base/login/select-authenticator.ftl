<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("selectAuthenticator")}
    <#elseif section = "form">
            <div class="list-group list-view-pf">
                <div class="list-group-item list-view-pf-stacked">
                    <div class="list-view-pf-main-info">
                        <div class="list-view-pf-left">
                            <span class="fa fa-unlock list-view-pf-icon-lg"></span>
                        </div>
                        <div class="list-view-pf-body">
                            <div class="list-view-pf-description">
                                <div class="list-group-item-heading">
                                    Password
                                </div>
                                <div class="list-group-item-text">
                                    Log in by entering your password.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="list-group-item list-view-pf-stacked">
                    <div class="list-view-pf-main-info">
                        <div class="list-view-pf-left">
                            <span class="fa fa-mobile list-view-pf-icon-lg"></span>
                        </div>
                        <div class="list-view-pf-body">
                            <div class="list-view-pf-description">
                                <div class="list-group-item-heading">
                                    Authenticator Application
                                </div>
                                <div class="list-group-item-text">
                                    Enter a verification code from authenticator applicationN.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="list-group-item list-view-pf-stacked">
                    <div class="list-view-pf-main-info">
                        <div class="list-view-pf-left">
                            <span class="fa fa-key list-view-pf-icon-lg"></span>
                        </div>
                        <div class="list-view-pf-body">
                            <div class="list-view-pf-description">
                                <div class="list-group-item-heading">
                                    Security Key
                                </div>
                                <div class="list-group-item-text">
                                    Use your security key to log in.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        <form id="kc-select-credential-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="authenticators-choice" class="${properties.kcLabelClass!}">${msg("loginCredential")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <select id="authenticators-choice" class="form-control" size="1">
                        <#list auth.authenticationSelections as authenticationSelection>
                            <option value="${authenticationSelection.authExecId}" <#if authenticationSelection.authExecId == execution>selected</#if>>${msg('${authenticationSelection.authExecDisplayName}')}</option>
                        </#list>
                    </select>
                    <input type="hidden" id="authexec-hidden-input" name="authenticationExecution" />
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>

