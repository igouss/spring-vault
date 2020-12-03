/*
 * Copyright 2018-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.vault.authentication;

import java.io.IOException;
import java.util.function.Supplier;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

/**
 * Interface to obtain a {@link ServiceAccountCredentials} for GCP IAM authentication.
 * Implementations are used by {@link GcpIamAuthentication}.
 *
 * @author Mark Paluch
 * @since 2.1
 * @see GcpIamAuthentication
 */
@FunctionalInterface
public interface GcpCredentialSupplier extends Supplier<GoogleCredentials> {

	/**
	 * Exception-safe helper to get {@link ServiceAccountCredentials} from {@link #getCredential}.
	 * @return the GoogleCredential for JWT signing.
	 */
	@Override
	default ServiceAccountCredentials get() {

		try {
			return getCredential();
		}
		catch (IOException e) {
			throw new IllegalStateException("Cannot obtain GoogleCredential", e);
		}
	}

	/**
	 * Get a {@link ServiceAccountCredentials} for GCP IAM authentication via JWT signing.
	 * @return the {@link ServiceAccountCredentials}.
	 * @throws IOException if the credential lookup fails.
	 */
	ServiceAccountCredentials getCredential() throws IOException;

}
