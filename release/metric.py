"""Immutable values used by the aggregate-only release pipeline."""

from dataclasses import asdict, dataclass
from decimal import Decimal, ROUND_HALF_UP, localcontext


def high_precision_percentage(numerator: int, denominator: int) -> Decimal:
    """Return a deterministic high-precision Decimal percentage, never a float."""
    if denominator < 0 or numerator < 0:
        raise ValueError("metric counts must not be negative")
    if numerator > denominator:
        raise ValueError("a metric numerator must not exceed its denominator")
    if denominator == 0:
        return Decimal("0")
    # A percentage such as 5/7 is recurring. A fixed Decimal precision makes
    # the retained high-precision value deterministic without float math.
    with localcontext() as context:
        context.prec = 50
        return Decimal(numerator) * Decimal("100") / Decimal(denominator)


def display_percentage(value: Decimal, precision: int) -> str:
    """Render a Decimal using the declared, half-up display precision."""
    if precision < 0:
        raise ValueError("percentage precision must be non-negative")
    quantum = Decimal(1).scaleb(-precision)
    return format(value.quantize(quantum, rounding=ROUND_HALF_UP), f".{precision}f")


@dataclass(frozen=True, slots=True)
class Metric:
    """A public, aggregate-only measurement with an explicit denominator."""

    metric_id: str
    category: str
    numerator: int
    denominator: int
    denominator_metric_id: str | None
    percentage: Decimal
    display_percentage: str
    precision: int
    population: str
    unit: str
    measurement_period: str
    method: str
    caveat: str

    @classmethod
    def counted(
        cls,
        *,
        metric_id: str,
        category: str,
        numerator: int,
        denominator: int,
        denominator_metric_id: str | None,
        population: str,
        measurement_period: str,
        method: str,
        caveat: str,
        precision: int = 2,
        unit: str = "domains",
    ) -> "Metric":
        percentage = high_precision_percentage(numerator, denominator)
        return cls(
            metric_id=metric_id,
            category=category,
            numerator=numerator,
            denominator=denominator,
            denominator_metric_id=denominator_metric_id,
            percentage=percentage,
            display_percentage=display_percentage(percentage, precision),
            precision=precision,
            population=population,
            unit=unit,
            measurement_period=measurement_period,
            method=method,
            caveat=caveat,
        )

    def to_dict(self) -> dict:
        """Return a JSON-safe representation preserving Decimal precision."""
        value = asdict(self)
        value["percentage"] = format(self.percentage, "f")
        return value
