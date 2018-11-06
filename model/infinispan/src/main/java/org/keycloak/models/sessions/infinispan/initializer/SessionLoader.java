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

package org.keycloak.models.sessions.infinispan.initializer;

import java.io.Serializable;
import java.util.List;

import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface SessionLoader<LOADER_CONTEXT extends SessionLoader.LoaderContext, WORKER_RESULT extends SessionLoader.WorkerResult> extends Serializable {

    /**
     * Will be triggered just once on cluster coordinator node to perform some generic initialization tasks (Eg. update DB before starting load).
     *
     * NOTE: This shouldn't be used for the initialization of loader instance itself!
     *
     * @param session
     */
    void init(KeycloakSession session);


    /**
     *
     * Will be triggered just once on cluster coordinator node to count the number of segments and other context data specific to the worker task.
     * Each segment will be then later computed in one "worker" task
     *
     * This method could be expensive to call, so the "computed" loaderContext object is passed among workers/loaders and needs to be serializable
     *
     * @param session
     * @return
     */
    LOADER_CONTEXT computeInitialLoaderContext(KeycloakSession session);


    // TODO:mposolda javadoc etc
    LOADER_CONTEXT computeLoaderContext(KeycloakSession session, int workerId, List<WORKER_RESULT> previousResults);


    /**
     * Will be called on all cluster nodes to load the specified page.
     *
     * @param session
     * @param loaderContext loaderContext object, which was already computed before
     * @param segment to be computed
     * @return
     */
    WORKER_RESULT loadSessions(KeycloakSession session, LOADER_CONTEXT loaderContext, int segment);


    WORKER_RESULT createFailedWorkerResult(LOADER_CONTEXT loaderContext);


    /**
     * This will be called on nodes to check if loading is finished. It allows loader to notify that loading is finished for some reason.
     *
     * @param initializer
     * @return
     */
    boolean isFinished(BaseCacheInitializer initializer);


    /**
     * Callback triggered on cluster coordinator once it recognize that all sessions were successfully loaded
     *
     * @param initializer
     */
    void afterAllSessionsLoaded(BaseCacheInitializer initializer);


    /**
     * Object, which contains some context data to be used by SessionLoader implementation. It's computed just once and then passed
     * to each {@link SessionLoader}. It needs to be {@link Serializable}
     */
    interface LoaderContext extends Serializable {

        int getSegmentsCount();

        int getSegment();

        int getWorkerId();

    }


    interface WorkerResult {

        boolean wasSuccessComputation();

        int getSegment();



    }
}
