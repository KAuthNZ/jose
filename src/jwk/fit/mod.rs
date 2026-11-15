mod errors;

mod candidates;

mod mode_operations;

#[cfg(test)]
mod tests;

pub use errors::FitErrors;

pub(crate) use candidates::Candidates;
