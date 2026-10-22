package fr.supdevinci.argus.clients.epss;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.test.autoconfigure.RestClientTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.HttpClientErrorException;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Teste le client EPSS sans appel réseau.
 */
@RestClientTest(value = EpssClient.class, properties = "argus.epss.url=https://epss.test/epss")
class EpssClientTest {

    private static final String EMPTY_RESPONSE = """
            {"status": "OK", "data": []}
            """;

    @Autowired
    private EpssClient epssClient;

    @Autowired
    private MockRestServiceServer server;

    @Test
    void fetchScores_sendsCveIdsInOneRequestAndMapsScores() {
        server.expect(requestTo("https://epss.test/epss?cve=CVE-2021-44228,CVE-2023-4966&limit=2"))
                .andExpect(method(GET))
                .andRespond(withSuccess(new ClassPathResource("epss/scores.json"), MediaType.APPLICATION_JSON));

        List<EpssScoreResponse> scores = epssClient.fetchScores(List.of("CVE-2021-44228", "CVE-2023-4966"));

        assertThat(scores).hasSize(2);

        EpssScoreResponse citrixBleed = scores.getFirst();
        assertThat(citrixBleed.cve()).isEqualTo("CVE-2023-4966");
        assertThat(citrixBleed.epss()).isEqualTo(0.99999);
        assertThat(citrixBleed.percentile()).isEqualTo(0.99997);
        assertThat(citrixBleed.date()).isEqualTo(LocalDate.of(2026, 10, 22));

        server.verify();
    }

    @Test
    void fetchScores_splitsLargeListsIntoBatches() {
        List<String> cveIds = IntStream.rangeClosed(1, EpssClient.BATCH_SIZE + 50)
                .mapToObj(number -> "CVE-2026-" + number)
                .toList();

        // 150 CVE donnent un premier lot de 100 puis un second lot de 50.
        server.expect(queryParam("limit", "100"))
                .andRespond(withSuccess(EMPTY_RESPONSE, MediaType.APPLICATION_JSON));
        server.expect(queryParam("limit", "50"))
                .andRespond(withSuccess(EMPTY_RESPONSE, MediaType.APPLICATION_JSON));

        epssClient.fetchScores(cveIds);

        server.verify();
    }

    @Test
    void fetchScores_withEmptyList_sendsNoRequest() {
        List<EpssScoreResponse> scores = epssClient.fetchScores(List.of());

        assertThat(scores).isEmpty();
        server.verify();
    }

    @Test
    void fetchScores_throwsWhenRateLimitIsExceeded() {
        server.expect(requestTo("https://epss.test/epss?cve=CVE-2021-44228&limit=1"))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));

        assertThatThrownBy(() -> epssClient.fetchScores(List.of("CVE-2021-44228")))
                .isInstanceOf(HttpClientErrorException.TooManyRequests.class);
    }
}
