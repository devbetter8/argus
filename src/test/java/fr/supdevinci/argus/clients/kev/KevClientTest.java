package fr.supdevinci.argus.clients.kev;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.HttpServerErrorException;

import java.time.Instant;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.http.HttpMethod.GET;

/**
 * Teste le client KEV sans appel réseau.
 * MockRestServiceServer remplace l'API de la CISA par une réponse simulée.
 */
@RestClientTest(value = KevClient.class, properties = "argus.kev.url=https://kev.test/catalog.json")
class KevClientTest {

    private static final String KEV_URL = "https://kev.test/catalog.json";

    @Autowired
    private KevClient kevClient;

    @Autowired
    private MockRestServiceServer server;

    @Test
    void fetchCatalog_mapsCatalogAndVulnerabilities() {
        server.expect(requestTo(KEV_URL))
                .andExpect(method(GET))
                .andRespond(withSuccess(new ClassPathResource("kev/catalog.json"), MediaType.APPLICATION_JSON));

        KevCatalogResponse catalog = kevClient.fetchCatalog();

        assertThat(catalog.catalogVersion()).isEqualTo("2026.10.21");
        assertThat(catalog.dateReleased()).isEqualTo(Instant.parse("2026-10-21T14:04:39.8983Z"));
        assertThat(catalog.count()).isEqualTo(2);
        assertThat(catalog.vulnerabilities()).hasSize(2);

        KevVulnerabilityResponse log4shell = catalog.vulnerabilities().getFirst();
        assertThat(log4shell.cveId()).isEqualTo("CVE-2021-44228");
        assertThat(log4shell.vendorProject()).isEqualTo("Apache");
        assertThat(log4shell.product()).isEqualTo("Log4j2");
        assertThat(log4shell.dateAdded()).isEqualTo(LocalDate.of(2021, 12, 10));
        assertThat(log4shell.dueDate()).isEqualTo(LocalDate.of(2021, 12, 24));
        assertThat(log4shell.knownRansomwareCampaignUse()).isEqualTo("Known");

        server.verify();
    }

    @Test
    void fetchCatalog_throwsWhenServerFails() {
        server.expect(requestTo(KEV_URL))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> kevClient.fetchCatalog())
                .isInstanceOf(HttpServerErrorException.class);
    }
}
