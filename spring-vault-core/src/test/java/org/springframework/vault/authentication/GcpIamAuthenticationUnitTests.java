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
import java.time.Duration;
import com.google.api.client.testing.http.MockHttpTransport;
import com.google.api.client.testing.http.MockLowLevelHttpResponse;
import com.google.auth.oauth2.ServiceAccountCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.vault.client.VaultClients.PrefixAwareUriTemplateHandler;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Unit tests for {@link GcpIamAuthentication}.
 *
 * @author Mark Paluch
 */
class GcpIamAuthenticationUnitTests {

    RestTemplate restTemplate;

    MockRestServiceServer mockRest;

    MockHttpTransport mockHttpTransport;

    @BeforeEach
    void before() {

        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setUriTemplateHandler(new PrefixAwareUriTemplateHandler());

        this.mockRest = MockRestServiceServer.createServer(restTemplate);
        this.restTemplate = restTemplate;
    }

    @Test
    void shouldLogin() {

        MockLowLevelHttpResponse response = new MockLowLevelHttpResponse();
        response.setStatusCode(200);
        response.setContent("{\"keyId\":\"keyid\", \"signedJwt\":\"my-jwt\"}");

        this.mockHttpTransport = new MockHttpTransport.Builder().setLowLevelHttpResponse(response).build();

        this.mockRest.expect(requestTo("/auth/gcp/login")).andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.role").value("dev-role")).andExpect(jsonPath("$.jwt").value("my-jwt"))
                .andRespond(withSuccess().contentType(MediaType.APPLICATION_JSON).body(
                        "{" + "\"auth\":{\"client_token\":\"my-token\", \"renewable\": true, \"lease_duration\": 10}"
                                + "}"));

        PrivateKey privateKeyMock = mock(PrivateKey.class);
        ServiceAccountCredentials credential = ServiceAccountCredentials.newBuilder()
                .setClientEmail("hello@world")
                .setProjectId("foobar")
                .setPrivateKey(privateKeyMock)
                .setPrivateKeyId("key-id")
                .build();

        GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder().role("dev-role")
                .credential(credential).build();
        GcpIamAuthentication authentication = new GcpIamAuthentication(options, this.restTemplate,
                this.mockHttpTransport);

        VaultToken login = authentication.login();

        assertThat(login).isInstanceOf(LoginToken.class);
        assertThat(login.getToken()).isEqualTo("my-token");

        LoginToken loginToken = (LoginToken) login;
        assertThat(loginToken.isRenewable()).isTrue();
        assertThat(loginToken.getLeaseDuration()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void shouldCreateNewGcpIamObjectInstance() {

        PrivateKey privateKeyMock = mock(PrivateKey.class);
        ServiceAccountCredentials credential = ServiceAccountCredentials.newBuilder()
                .setClientEmail("hello@world")
                .setProjectId("foobar")
                .setPrivateKey(privateKeyMock)
                .setPrivateKeyId("key-id")
                .build();

        GcpIamAuthenticationOptions options = GcpIamAuthenticationOptions.builder()
                .role("dev-role")
                .credential(credential)
                .build();

        new GcpIamAuthentication(options, this.restTemplate);
    }

}
