package greencity.dto.econews;

import greencity.dto.user.PlaceAuthorDto;
import java.time.ZonedDateTime;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
@Builder
@EqualsAndHashCode
public class EcoNewsForSendEmailDto {
    @NotBlank
    private String unsubscribeToken;

    @NotNull
    private ZonedDateTime creationDate;

    @NotBlank
    private String imagePath;

    @NotBlank
    private String source;

    @NotNull
    @Valid
    private PlaceAuthorDto author;

    @NotBlank
    private String title;

    @NotBlank
    private String text;
}
