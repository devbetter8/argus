package fr.supdevinci.argus.clients.nvd;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.test.web.client.ExpectedCount.times;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Teste le client NVD sans appel réseau.
 * La pause entre les requêtes est désactivée pour garder des tests rapides.
 */
@RestClientTest(value = NvdClient.class, properties = {
        "argus.nvd.url=https://nvd.test/cves",
        "argus.nvd.api-key=test-key",
        "argus.nvd.request-delay=0s"
})
class NvdClientTest {

    private static final LocalDateTime START = LocalDateTime.of(2026, 10, 1, 0, 0);
    private static final LocalDateTime END = LocalDateTime.of(2026, 10, 22, 12, 30);

    @Autowired
    private NvdClient nvdClient;

    @Autowired
    private MockRestServiceServer server;

    @Test
    void fetchPublishedBetween_sendsExpectedRequestAndMapsCves() {
        server.expect(requestTo("https://nvd.test/cves"
                        + "?pubStartDate=2026-10-01T00:00:00.000"
                        + "&pubEndDate=2026-10-22T12:30:00.000"
                        + "&resultsPerPage=500&startIndex=0&noRejected"))
                .andExpect(method(GET))
                .andExpect(header("apiKey", "test-key"))
                .andRespond(withSuccess(new ClassPathResource("nvd/page.json"), MediaType.APPLICATION_JSON));

        List<NvdCvePageResponse.Cve> cves = nvdClient.fetchPublishedBetween(START, END);

        assertThat(cves).extracting(NvdCvePageResponse.Cve::id)
                .containsExactly("CVE-2021-44228", "CVE-2026-12345");

        NvdCvePageResponse.Cve log4shell = cves.getFirst();
        assertThat(log4shell.published()).isEqualTo(LocalDateTime.of(2021, 12, 10, 10, 15, 9, 143_000_000));
        assertThat(log4shell.vulnStatus()).isEqualTo("Analyzed");
        assertThat(log4shell.descriptions()).hasSize(2);

        NvdCvePageResponse.CvssMetric cvss31 = log4shell.metrics().cvssMetricV31().getFirst();
        assertThat(cvss31.type()).isEqualTo("Primary");
        assertThat(cvss31.cvssData().baseScore()).isEqualTo(10.0);
        assertThat(cvss31.cvssData().baseSeverity()).isEqualTo("CRITICAL");

        // Une CVE pas encore analysée n'a aucun score.
        NvdCvePageResponse.Cve notAnalyzed = cves.get(1);
        assertThat(notAnalyzed.metrics().cvssMetricV31()).isNull();

        server.verify();
    }

    @Test
    void fetchModifiedBetween_usesLastModifiedParameters() {
        server.expect(queryParam("lastModStartDate", "2026-10-01T00:00:00.000"))
                .andExpect(queryParam("lastModEndDate", "2026-10-22T12:30:00.000"))
                .andRespond(withSuccess(page(0, 0), MediaType.APPLICATION_JSON));

        List<NvdCvePageResponse.Cve> cves = nvdClient.fetchModifiedBetween(START, END);

        assertThat(cves).isEmpty();
        server.verify();
    }

    @Test
    void fetchPublishedBetween_readsAllPages() {
        // 3 résultats au total : 2 sur la première page, 1 sur la seconde.
        server.expect(queryParam("startIndex", "0"))
                .andRespond(withSuccess(page(0, 3, cve("CVE-2026-0001"), cve("CVE-2026-0002")),
                        MediaType.APPLICATION_JSON));
        server.expect(queryParam("startIndex", "2"))
                .andRespond(withSuccess(page(2, 3, cve("CVE-2026-0003")), MediaType.APPLICATION_JSON));

        List<NvdCvePageResponse.Cve> cves = nvdClient.fetchPublishedBetween(START, END);

        assertThat(cves).extracting(NvdCvePageResponse.Cve::id)
                .containsExactly("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003");
        server.verify();
    }

    @Test
    void fetchPublishedBetween_rejectsRangeOverMaximum() {
        LocalDateTime tooLate = START.plus(NvdClient.MAX_DATE_RANGE).plusSeconds(1);

        assertThatThrownBy(() -> nvdClient.fetchPublishedBetween(START, tooLate))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fetchPublishedBetween_rejectsEndBeforeStart() {
        assertThatThrownBy(() -> nvdClient.fetchPublishedBetween(END, START))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fetchPublishedBetween_retriesAfterTemporaryFailure() {
        server.expect(queryParam("startIndex", "0"))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(queryParam("startIndex", "0"))
                .andRespond(withSuccess(page(0, 1, cve("CVE-2026-0001")), MediaType.APPLICATION_JSON));

        List<NvdCvePageResponse.Cve> cves = nvdClient.fetchPublishedBetween(START, END);

        assertThat(cves).hasSize(1);
        server.verify();
    }

    @Test
    void fetchPublishedBetween_throwsWhenAllRetriesFail() {
        server.expect(times(NvdClient.MAX_RETRIES + 1), queryParam("startIndex", "0"))
                .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));

        assertThatThrownBy(() -> nvdClient.fetchPublishedBetween(START, END))
                .isInstanceOf(HttpServerErrorException.ServiceUnavailable.class);
        server.verify();
    }

    @Test
    void fetchPublishedBetween_throwsWhenApiKeyIsRefused() {
        server.expect(header("apiKey", "test-key"))
                .andRespond(withStatus(HttpStatus.FORBIDDEN));

        assertThatThrownBy(() -> nvdClient.fetchPublishedBetween(START, END))
                .isInstanceOf(HttpClientErrorException.Forbidden.class);
        // Une seule requête : une clé refusée ne sert à rien de réessayer.
        server.verify();
    }

    private static String page(int startIndex, int totalResults, String... cves) {
        return """
                {"resultsPerPage": %d, "startIndex": %d, "totalResults": %d, "vulnerabilities": [%s]}
                """.formatted(cves.length, startIndex, totalResults, String.join(",", cves));
    }

    private static String cve(String id) {
        return """
                {"cve": {"id": "%s"}}
                """.formatted(id);
    }
}
