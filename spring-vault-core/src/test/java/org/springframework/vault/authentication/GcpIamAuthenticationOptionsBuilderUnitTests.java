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

import java.security.PrivateKey;

import com.google.auth.oauth2.ServiceAccountCredentials;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link GcpIamAuthenticationOptions}.
 *
 * @author Magnus Jungsbluth
 */
class GcpIamAuthenticationOptionsBuilderUnitTests {

	@Test
	void shouldDefaultToCredentialServiceAccountId() {

		ServiceAccountCredentials credential = createGoogleCredential();

		GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().credential(credential).role("foo")
				.build();

		assertThat(options.getServiceAccountIdAccessor().getServiceAccountId(credential)).isEqualTo("hello@world");
	}

	@Test
	void shouldAllowServiceAccountIdOverride() {

		ServiceAccountCredentials credential = createGoogleCredential();

		GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().credential(credential)
				.serviceAccountId("override@foo.com").role("foo").build();

		assertThat(options.getServiceAccountIdAccessor().getServiceAccountId(credential)).isEqualTo("override@foo.com");
	}

	@Test
	void shouldAllowServiceAccountIdProviderOverride() {

		ServiceAccountCredentials credential = createGoogleCredential();

		GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().credential(credential)
				.serviceAccountIdAccessor((ServiceAccountCredentials googleCredential) -> "override@foo.com").role("foo")
				.build();

		assertThat(options.getServiceAccountIdAccessor().getServiceAccountId(credential)).isEqualTo("override@foo.com");
	}

	@Test
	void shouldDefaultToCredentialProjectId() {

		ServiceAccountCredentials credential = createGoogleCredential();

		GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().credential(credential).role("foo")
				.build();

		assertThat(options.getProjectIdAccessor().getProjectId(credential)).isEqualTo("project-id");
	}

	@Test
	void shouldAllowProjectIdOverride() {

		ServiceAccountCredentials credential = createGoogleCredential();

		GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().credential(credential)
				.projectId("my-project").role("foo").build();

		assertThat(options.getProjectIdAccessor().getProjectId(credential)).isEqualTo("my-project");
	}

	@Test
	void shouldAllowProjectIdProviderOverride() {

		ServiceAccountCredentials credential = createGoogleCredential();

		GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().credential(credential)
				.projectIdAccessor((ServiceAccountCredentials googleCredential) -> "my-project").role("foo").build();

		assertThat(options.getProjectIdAccessor().getProjectId(credential)).isEqualTo("my-project");
	}

	private static ServiceAccountCredentials createGoogleCredential() {
		return ServiceAccountCredentials.newBuilder()
				.setClientEmail("hello@world")
				.setProjectId("project-id")
				.setPrivateKey(mock(PrivateKey.class))
				.setPrivateKeyId("key-id")
				.build();
	}

}
