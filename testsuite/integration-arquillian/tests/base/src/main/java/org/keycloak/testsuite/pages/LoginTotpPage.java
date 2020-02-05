/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.testsuite.pages;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class LoginTotpPage extends LanguageComboboxAwarePage {

    @FindBy(id = "otp")
    private WebElement otpInput;

    @FindBy(id = "password-token")
    private WebElement passwordToken;

    @FindBy(css = "input[type=\"submit\"]")
    private WebElement submitButton;

    @FindBy(className = "alert-error")
    private WebElement loginErrorMessage;

    @FindBy(className = "card-pf-view-single-select")
    private WebElement credentialCard;

    public void login(String totp) {
        otpInput.clear();
        if (totp != null) otpInput.sendKeys(totp);

        submitButton.click();
    }

    public String getError() {
        return loginErrorMessage != null ? loginErrorMessage.getText() : null;
    }

    public boolean isCurrent() {
        try {
            driver.findElement(By.id("otp"));
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public void open() {
        throw new UnsupportedOperationException();
    }


    // If false, we don't expect that credentials combobox is available. If true, we expect that it is available on the page
    public void assertOtpCredentialSelectorAvailability(boolean expectedAvailability) {
        try {
            driver.findElement(By.className("card-pf-view-single-select"));
            Assert.assertTrue(expectedAvailability);
        } catch (NoSuchElementException nse) {
            Assert.assertFalse(expectedAvailability);
        }
    }


    public List<String> getAvailableOtpCredentials() {

        return driver.findElements(By.xpath("//div[contains(@class, 'card-pf-view-single-select')]//h2"))
                .stream().map(WebElement::getText).collect(Collectors.toList());
    }


    public String getSelectedOtpCredential() {
        Assert.assertFalse(credentialCard.getAttribute("class").contains("active"));
        credentialCard.click();
        Assert.assertTrue(credentialCard.getAttribute("class").contains("active"));
        return credentialCard.findElement(By.tagName("h2")).getText();
    }


    public void selectOtpCredential(String credentialName) {
        WebElement webElement = driver.findElement(
                By.xpath("//div[contains(@class, 'card-pf-view-single-select')]//h2[normalize-space() = '"+ credentialName +"']"));
        webElement.click();
    }

}