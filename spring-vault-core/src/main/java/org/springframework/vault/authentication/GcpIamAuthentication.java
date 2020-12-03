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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.api.client.googleapis.apache.GoogleApacheHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;

import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.iam.credentials.v1.IamCredentialsClient;
import com.google.cloud.iam.credentials.v1.ServiceAccountName;
import com.google.cloud.iam.credentials.v1.SignJwtRequest;
import com.google.cloud.iam.credentials.v1.SignJwtResponse;
import org.springframework.util.Assert;
import org.springframework.vault.VaultException;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestOperations;

/**
 * GCP IAM login implementation using GCP IAM service accounts to legitimate its
 * authenticity via JSON Web Token.
 * <p/>
 * This authentication method uses Googles IAM API to obtain a signed token for a specific
 * {@link com.google.api.client.auth.oauth2.Credential}. Project and service account
 * details are obtained from a {@link ServiceAccountCredentials} that can be retrieved either from
 * a JSON file or the runtime environment (GAE, GCE).
 * <p/>
 * {@link GcpIamAuthentication} uses Google Java API that uses synchronous API.
 *
 * @author Mark Paluch
 * @author Magnus Jungsbluth
 * @since 2.1
 * @see GcpIamAuthenticationOptions
 * @see HttpTransport
 * @see ServiceAccountCredentials
 * @see ServiceAccountCredentials#getApplicationDefault()
 * @see RestOperations
 * @see <a href="https://www.vaultproject.io/docs/auth/gcp.html">Auth Backend: gcp
 * (IAM)</a>
 * @see <a href=
 * "https://cloud.google.com/iam/reference/rest/v1/projects.serviceAccounts/signJwt">GCP:
 * projects.serviceAccounts.signJwt</a>
 */
public class GcpIamAuthentication extends GcpJwtAuthenticationSupport implements ClientAuthentication {

	private static final JsonFactory JSON_FACTORY = new JacksonFactory();

	private final GcpIamAuthenticationOptions options;

	private final HttpTransport httpTransport;

	private final ServiceAccountCredentials credential;

	/**
	 * Create a new instance of {@link GcpIamAuthentication} given
	 * {@link GcpIamAuthenticationOptions} and {@link RestOperations}. This constructor
	 * initializes {@link GoogleApacheHttpTransport} for Google API usage.
	 * @param options must not be {@literal null}.
	 * @param restOperations HTTP client for for Vault login, must not be {@literal null}.
	 */
	public GcpIamAuthentication(GcpIamAuthenticationOptions options, RestOperations restOperations) {
		this(options, restOperations, new NetHttpTransport());
	}

	/**
	 * Create a new instance of {@link GcpIamAuthentication} given
	 * {@link GcpIamAuthenticationOptions}, {@link RestOperations} and
	 * {@link HttpTransport}.
	 * @param options must not be {@literal null}.
	 * @param restOperations HTTP client for for Vault login, must not be {@literal null}.
	 * @param httpTransport HTTP client for Google API use, must not be {@literal null}.
	 */
	public GcpIamAuthentication(GcpIamAuthenticationOptions options, RestOperations restOperations,
			HttpTransport httpTransport) {

		super(restOperations);

		Assert.notNull(options, "GcpIamAuthenticationOptions must not be null");
		Assert.notNull(restOperations, "RestOperations must not be null");
		Assert.notNull(httpTransport, "HttpTransport must not be null");

		this.options = options;
		this.httpTransport = httpTransport;
		this.credential = options.getCredentialSupplier().get();
	}

	@Override
	public VaultToken login() throws VaultException {

		String signedJwt = signJwt();

		return doLogin("GCP-IAM", signedJwt, this.options.getPath(), this.options.getRole());
	}

	protected String signJwt() {
		String projectId = getProjectId();
		String serviceAccount = getServiceAccountId();
		Map<String, Object> jwtPayload = getJwtPayload(this.options, serviceAccount);

		// TODO: Figure out how to set httpTransport on IamCredentialsClient
		try (IamCredentialsClient iamCredentialsClient = IamCredentialsClient.create()) {
			ServiceAccountName name = ServiceAccountName.of(projectId, serviceAccount);
			String payload = JSON_FACTORY.toString(jwtPayload);
			SignJwtRequest request = SignJwtRequest.newBuilder()
					.setName(name.toString())
					.setPayload(payload)
					.build();
			SignJwtResponse response = iamCredentialsClient.signJwt(request);
			return response.getSignedJwt();
		}
		catch (IOException e) {
			throw new VaultLoginException("Cannot sign JWT", e);
		}
	}

	private String getServiceAccountId() {
		return this.options.getServiceAccountIdAccessor().getServiceAccountId(this.credential);
	}

	private String getProjectId() {
		return this.options.getProjectIdAccessor().getProjectId(this.credential);
	}

	private static Map<String, Object> getJwtPayload(GcpIamAuthenticationOptions options, String serviceAccount) {

		Instant validUntil = options.getClock().instant().plus(options.getJwtValidity());

		Map<String, Object> payload = new LinkedHashMap<>();

		payload.put("sub", serviceAccount);
		payload.put("aud", "vault/" + options.getRole());
		payload.put("exp", validUntil.getEpochSecond());

		return payload;
	}

}
