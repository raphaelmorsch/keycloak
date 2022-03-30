/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
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
 *
 */

package org.keycloak.testsuite.script;

import javax.script.Bindings;
import javax.script.Compilable;
import javax.script.CompiledScript;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.ScriptModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.scripting.DefaultScriptingProvider;
import org.keycloak.scripting.Script;
import org.keycloak.scripting.ScriptCompilationException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ScriptTest {

    private static final Logger log = Logger.getLogger(ScriptTest.class);

    private ScriptEngineManager scriptEngineManager;

    private ScriptEngine scriptEngine;

    private CompiledScript compiledScript;

    private static final String SCRIPT = "if (typeof token1 !== 'undefined') print('token1: ' + token1);\nif (typeof token2 !== 'undefined') print('token2: ' + token2);\nif (typeof token3 !== 'undefined') print('token3: ' + token3);\ntoken.audience(\"some-other-audii\");\nexports = true;";

    private static final int TOTAL = 10;

    private static final int PER_ITERATION = 1;

    public static void main(String[] args) {
        log.info("ScriptTest executed");

        // Step 1: Get script manager
        new ScriptTest().runTest();
    }

    public void runTest() {
        // Step 1: Script Engine Manager
        createScriptEngineManager();

        int start = Time.currentTime();

        for (int i = 0; i < TOTAL ; i++) {
            AccessToken token = runTestIteration(i);
            if (i % PER_ITERATION == 0) {
                log.infof("Executed %d iterations. Time since start: %d", i, (Time.currentTime() - start));
            }
        }
    }

    private AccessToken runTestIteration(int iteration) {
        ScriptModel scriptModel = new Script(null /* scriptId */, "foo", "token-mapper-script_111", ScriptModel.TEXT_JAVASCRIPT, SCRIPT, null);
        // This can be shared
        if (scriptEngine == null) {
            // Step 2: Script engine
            scriptEngine = createPreparedScriptEngine(scriptModel);
            //compiledScript = tryCompile(scriptModel, (Compilable) scriptEngine);
        }

        // Step 3: Create script
        CompiledScript compiledScript = tryCompile(scriptModel, (Compilable) scriptEngine);

        // Step 4: Create bindings
        AccessToken accessToken = new AccessToken();
        Bindings bindings = createBindings(scriptEngine, accessToken, iteration);

        // Step 5: Eval
        evalUnchecked(compiledScript, bindings);

        return accessToken;
    }


    private ScriptEngineManager createScriptEngineManager() {
        if (scriptEngineManager == null) {
            synchronized (this) {
                if (scriptEngineManager == null) {
                    scriptEngineManager = new ScriptEngineManager();
                }
            }
        }
        return scriptEngineManager;
    }

    /**
     * Looks-up a {@link ScriptEngine} with prepared {@link Bindings} for the given {@link ScriptModel Script}.
     */
    private ScriptEngine createPreparedScriptEngine(ScriptModel script) {
        ScriptEngine scriptEngine = lookupScriptEngineFor(script);

        if (scriptEngine == null) {
            throw new IllegalStateException("Could not find ScriptEngine for script: " + script);
        }

        return scriptEngine;
    }

    /**
     * Looks-up a {@link ScriptEngine} based on the MIME-type provided by the given {@link Script}.
     */
    private ScriptEngine lookupScriptEngineFor(ScriptModel script) {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(DefaultScriptingProvider.class.getClassLoader());
            return scriptEngineManager.getEngineByMimeType(script.getMimeType());
        }
        finally {
            Thread.currentThread().setContextClassLoader(cl);
        }
    }

    private CompiledScript tryCompile(ScriptModel scriptModel, Compilable engine) {
        try {
            return engine.compile(scriptModel.getCode());
        } catch (ScriptException e) {
            throw new ScriptCompilationException(scriptModel, e);
        }
    }

    private Bindings createBindings(ScriptEngine scriptEngine, AccessToken accessToken, int iteration) {
        final Bindings bindings = scriptEngine.createBindings();
        // Just to test that bindings is not shared
        switch (iteration % 3) {
            case 0:
                bindings.put("token3", accessToken);
                break;
            case 1:
                bindings.put("token1", accessToken);
                break;
            case 2:
                bindings.put("token2", accessToken);
                break;
        }

        bindings.put("token", accessToken);
        return bindings;
    }

    private Object evalUnchecked(CompiledScript compiledScript, Bindings bindings) {
        try {
            return compiledScript.eval(bindings);
        } catch (ScriptException e) {
            throw new IllegalStateException("Failed to evaluate script", e);
        }
    }
}
