package fr.supdevinci.argus;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(TestcontainersConfiguration.class)
@SpringBootTest(properties = {"argus.nvd.api-key=test-key", "argus.sync.enabled=false"})
class ArgusApplicationTests {

    @Test
    void contextLoads() {
    }

}
