<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayWide=false>
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <form id="kc-select-credential-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
          <select name="cars">
            <option value="volvo">Volvo</option>
            <option value="saab">Saab</option>
            <option value="fiat">Fiat</option>
            <option value="audi">Audi</option>
          </select>
          <br><br>
          <input type="submit" name="select_credential" value = "Select credential">
        </form>
        <br><br>
        <#nested "form">
    </#if>
</@layout.registrationLayout>
</#macro>