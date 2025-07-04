package zone.cogni.lib.security.common;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;

import java.net.MalformedURLException;

public class ResourceHelper {

  // copied from zone.cogni.core.spring.ResourceHelper in zone.cogni.asquare:cogni-core (it's the only use of asquare)
  public static Resource getResourceFromUrl(String url) {
    if (url.startsWith("classpath:")) {
      return new ClassPathResource(url.substring(10));
    }
    try {
      return new UrlResource(url);
    }
    catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }
  }
}
