// Reorders predicates by cost (cheapest first) and pushes cheap filters
// as close to the event source as possible — ideally into eBPF XDP hook.


pub struct PredicatePushdown;


impl PredicatePushdown {
    pub fn run(&self, mut mir: MirProgram) -> Result<MirProgram, CompileError> {
        for rule in &mut mir.rules {
            // Sort predicates ascending by cost — constant checks first
            rule.predicates.sort_by_key(|p| p.cost as u8);


            // Mark predicates that can run in eBPF (no string ops, no ML)
            for pred in &mut rule.predicates {
                pred.ebpf_eligible = matches!(
                    pred.cost,
                    PredicateCost::Constant | PredicateCost::FieldLookup | PredicateCost::SetLookup
                );
            }
        }
        Ok(mir)
    }
}




