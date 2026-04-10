use crate::crypto::GroupElement;
use serde::{Deserialize, Serialize};

/// Vector of group elements with batch operations
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupElementVector(Vec<GroupElement>);

impl GroupElementVector {
    /// Create a new group element vector
    pub fn new(elements: Vec<GroupElement>) -> Self {
        Self(elements)
    }

    /// Create from slice
    pub fn from_slice(elements: &[GroupElement]) -> Self {
        Self(elements.to_vec())
    }

    /// Get the number of elements
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get element at index
    pub fn get(&self, index: usize) -> Option<&GroupElement> {
        self.0.get(index)
    }

    /// Iterator over elements
    pub fn iter(&self) -> impl Iterator<Item = &GroupElement> {
        self.0.iter()
    }

    /// Convert to inner vector
    pub fn into_inner(self) -> Vec<GroupElement> {
        self.0
    }

    /// Reference to inner vector
    pub fn as_slice(&self) -> &[GroupElement] {
        &self.0
    }
}

impl FromIterator<GroupElement> for GroupElementVector {
    fn from_iter<I: IntoIterator<Item = GroupElement>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_element_vector_creation() {
        let elements = vec![GroupElement::infinity(), GroupElement::infinity()];
        let vec = GroupElementVector::new(elements);
        assert_eq!(vec.len(), 2);
    }
}
