export class DFANode {
  public readonly id: string;
  public readonly transitions: Map<string, DFANode>;
  public output: { pattern: string; weight: number } | null;

  constructor(
    id: string,
    transitions: Map<string, DFANode> = new Map(),
    output: { pattern: string; weight: number } | null = null
  ) {
    this.id = id;
    this.transitions = transitions;
    this.output = output;
  }

  next(ch: string): DFANode | undefined {
    return this.transitions.get(ch.toLowerCase());
  }
}
